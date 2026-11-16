import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from cryptography.fernet import Fernet

os.environ["DATABASE_URL"] = "sqlite:///unused-test.db"
import app


class ProposalVersionTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.database = patch.object(app, "DATABASE_URL", "sqlite:///" + str(Path(self.directory.name) / "test.db"))
        self.database.start()
        self.encryption = patch.dict(os.environ, {"DOCUMENT_ENCRYPTION_KEY": Fernet.generate_key().decode("ascii")})
        self.encryption.start()
        app._database_ready = False
        self.client = app.app.test_client()
        administrator = self.client.post("/api/auth/register", json={
            "name": "Admin", "email": "admin@example.com", "password": "password123"
        }).get_json()
        self.admin_id = administrator["user"]["id"]
        self.admin_headers = {"Authorization": "Bearer " + administrator["token"], "X-App-Role": "admin"}
        result = self.client.post("/api/auth/register", json={
            "name": "Student", "email": "student@example.com", "password": "password123"
        }).get_json()
        self.student_id = result["user"]["id"]
        self.headers = {"Authorization": "Bearer " + result["token"], "X-App-Role": "student"}

    def tearDown(self):
        self.database.stop()
        self.encryption.stop()
        app._database_ready = False
        self.directory.cleanup()

    def test_draft_changes_and_submission_preserve_versions(self):
        proposal = {"title": "First", "abstract": "Summary", "method": "Method",
                    "budget": 100, "months": 12, "outcomes": "Results", "status": "draft"}
        created = self.client.put("/api/collections/proposals/project", json={"data": proposal}, headers=self.headers)
        self.assertEqual(created.status_code, 200)
        updated = self.client.patch("/api/collections/proposals/project", json={"data": {"title": "Second"}}, headers=self.headers)
        self.assertEqual(updated.status_code, 200)
        submitted = self.client.patch("/api/collections/proposals/project", json={"data": {"status": "submitted"}}, headers=self.headers)
        self.assertEqual(submitted.status_code, 200)
        data = self.client.get("/api/collections/proposals", headers=self.headers).get_json()["docs"][0]["data"]
        self.assertEqual([version["number"] for version in data["versions"]], [1, 2, 3])
        self.assertEqual([version["data"]["title"] for version in data["versions"]], ["First", "Second", "Second"])
        self.assertEqual(data["versions"][-1]["data"]["status"], "submitted")
        stored = app.db_one("SELECT data FROM collection_documents WHERE collection = ? AND id = ?", ("proposals", "project"))["data"]
        self.assertNotIn("Summary", stored)
        self.assertNotIn("Second", stored)
        self.assertIn("encrypted_v1", stored)

    def test_experts_cannot_review_own_work_or_see_other_reviews(self):
        expert = self.client.post("/api/auth/register", json={
            "name": "Expert", "email": "expert@example.com", "password": "password123"
        }).get_json()
        admin_headers = self.admin_headers
        self.assertEqual(self.client.patch(
            "/api/collections/users/" + expert["user"]["id"],
            json={"data": {"isReviewer": True}}, headers=admin_headers
        ).status_code, 200)
        self.assertEqual(self.client.patch(
            "/api/collections/users/" + expert["user"]["id"],
            json={"data": {"isReviewer": "false"}}, headers=admin_headers
        ).status_code, 400)
        self.assertEqual(self.client.delete("/api/collections/users/" + expert["user"]["id"], headers=self.headers).status_code, 403)
        expert_headers = {"Authorization": "Bearer " + expert["token"], "X-App-Role": "reviewer"}
        proposal = {"title": "Project", "abstract": "Summary", "method": "Method",
                    "budget": 100, "months": 12, "outcomes": "Results", "status": "submitted"}
        self.assertEqual(self.client.put("/api/collections/proposals/project", json={"data": proposal}, headers=self.headers).status_code, 200)
        self.assertEqual(self.client.patch("/api/collections/proposals/project", json={"data": {
            "reviewers": ["not-a-user"]
        }}, headers=admin_headers).status_code, 400)
        review = {"scores": {criterion: 8 for criterion in app.REVIEW_CRITERIA}, "comment": "Confidential", "rec": "Финансировать"}
        self.assertEqual(self.client.patch("/api/collections/proposals/project", json={"data": {
            "reviews": {expert["user"]["id"]: {"scores": {}}}
        }}, headers=expert_headers).status_code, 400)
        self.assertEqual(self.client.patch("/api/collections/proposals/project", json={"data": {
            "reviews": {expert["user"]["id"]: review}
        }}, headers=expert_headers).status_code, 200)
        student_view = self.client.get("/api/collections/proposals", headers=self.headers).get_json()["docs"][0]["data"]
        self.assertEqual(student_view["reviews"], {})
        self.assertNotIn("reviewers", student_view)
        expert_view = self.client.get("/api/collections/proposals", headers=expert_headers).get_json()["docs"][0]["data"]
        self.assertNotIn("versions", expert_view)
        self.assertEqual(expert_view["reviews"], {expert["user"]["id"]: review})
        self.assertEqual(self.client.patch("/api/collections/proposals/project", json={"data": {
            "reviewers": [expert["user"]["id"]], "status": "review"
        }}, headers=admin_headers).status_code, 200)
        assigned_view = self.client.get("/api/collections/proposals", headers=expert_headers).get_json()["docs"][0]["data"]
        self.assertEqual(assigned_view["reviewers"], [expert["user"]["id"]])
        self.client.patch("/api/collections/users/" + self.student_id, json={"data": {"isReviewer": True}}, headers=admin_headers)
        self.assertEqual(self.client.get("/api/collections/proposals", headers={**self.headers, "X-App-Role": "reviewer"}).get_json()["docs"], [])
        events = self.client.get("/api/proposals/project/events", headers=admin_headers)
        self.assertEqual(events.status_code, 200)
        self.assertEqual([event["action"] for event in events.get_json()["events"]], ["created", "review", "updated"])
        self.assertEqual(events.get_json()["events"][1]["details"]["review"]["comment"], "Confidential")
        self.assertEqual(self.client.get("/api/proposals/project/events", headers=expert_headers).status_code, 403)

    def test_budget_milestones_require_approval_and_respect_budget(self):
        proposal = {"title": "Project", "abstract": "Summary", "method": "Method",
                    "budget": 100, "months": 12, "outcomes": "Results", "status": "submitted"}
        self.client.put("/api/collections/proposals/project", json={"data": proposal}, headers=self.headers)
        admin_headers = self.admin_headers
        milestone = {"title": "First payment", "amount": 80, "due_date": "2026-12-01",
                     "report_due": "2026-12-20", "status": "planned"}
        endpoint = "/api/collections/proposals/project"
        self.assertEqual(self.client.patch(endpoint, json={"data": {"milestones": [milestone]}}, headers=admin_headers).status_code, 400)
        with app.connection() as conn:
            record = app.get_document("proposals", "project")["data"]
            record["status"] = "approved"
        app.put_document("proposals", "project", record)
        self.assertEqual(self.client.patch(endpoint, json={"data": {"milestones": [milestone]}}, headers=admin_headers).status_code, 200)
        self.assertEqual(self.client.patch(endpoint, json={"data": {"milestones": [milestone, milestone]}}, headers=admin_headers).status_code, 400)
        self.assertEqual(self.client.patch(endpoint, json={"data": {"milestones": [milestone]}}, headers=self.headers).status_code, 403)
        report_url = "/api/proposals/project/reports"
        self.assertEqual(self.client.post(report_url, json={"milestone": 0, "text": "Progress report"}, headers=admin_headers).status_code, 403)
        self.assertEqual(self.client.post(report_url, json={"milestone": 1, "text": "Progress report"}, headers=self.headers).status_code, 400)
        self.assertEqual(self.client.post(report_url, json={"milestone": 0, "text": "Progress report"}, headers=self.headers).status_code, 201)
        proposal_data = self.client.get("/api/collections/proposals", headers=self.headers).get_json()["docs"][0]["data"]
        self.assertEqual(proposal_data["progressReports"][0]["text"], "Progress report")
        events = self.client.get("/api/proposals/project/events", headers=admin_headers).get_json()["events"]
        self.assertTrue(any("milestones" in event["details"] for event in events))
        self.assertTrue(any(event["action"] == "report" for event in events))

    def test_approval_stages_require_distinct_authorized_users_and_order(self):
        proposal = {"title": "Project", "abstract": "Summary", "method": "Method",
                    "budget": 100, "months": 12, "outcomes": "Results", "status": "submitted"}
        self.client.put("/api/collections/proposals/project", json={"data": proposal}, headers=self.headers)
        admin_headers = self.admin_headers
        endpoint = "/api/collections/proposals/project"
        self.assertEqual(self.client.patch(endpoint, json={"data": {"status": "approved"}}, headers=admin_headers).status_code, 403)
        stage_headers = []
        stage_accounts = []
        for stage in app.APPROVAL_STAGES:
            account = self.client.post("/api/auth/register", json={"name": stage, "email": stage + "@example.com", "password": "password123"}).get_json()
            self.assertEqual(self.client.patch("/api/collections/users/" + account["user"]["id"], json={"data": {"approvalRoles": [stage]}}, headers=admin_headers).status_code, 200)
            stage_accounts.append(account)
            stage_headers.append({"Authorization": "Bearer " + account["token"], "X-App-Role": stage})
        approval_url = "/api/proposals/project/approval"
        self.assertEqual(len(self.client.get("/api/collections/proposals", headers=stage_headers[0]).get_json()["docs"]), 1)
        self.assertEqual(self.client.get("/api/collections/proposals", headers=stage_headers[1]).get_json()["docs"], [])
        self.assertEqual(self.client.post(approval_url, json={"decision": "approve"}, headers=stage_headers[1]).status_code, 409)
        self.assertEqual(self.client.post(approval_url, json={"decision": "approve"}, headers=stage_headers[0]).status_code, 409)
        expert = self.client.post("/api/auth/register", json={"name": "Expert", "email": "expert2@example.com", "password": "password123"}).get_json()
        self.client.patch("/api/collections/users/" + expert["user"]["id"], json={"data": {"isReviewer": True}}, headers=admin_headers)
        expert_headers = {"Authorization": "Bearer " + expert["token"], "X-App-Role": "reviewer"}
        review = {"scores": {criterion: 8 for criterion in app.REVIEW_CRITERIA}, "comment": "Reviewed", "rec": "Финансировать"}
        self.assertEqual(self.client.patch(endpoint, json={"data": {"reviews": {expert["user"]["id"]: review}}}, headers=expert_headers).status_code, 200)
        self.client.patch("/api/collections/users/" + expert["user"]["id"], json={"data": {"approvalRoles": ["department_head"]}}, headers=admin_headers)
        self.assertEqual(self.client.post(approval_url, json={"decision": "approve"}, headers={**expert_headers, "X-App-Role": "department_head"}).status_code, 403)
        self.assertEqual(self.client.patch(endpoint, json={"data": {"reviewers": [expert["user"]["id"]], "status": "review"}}, headers=admin_headers).status_code, 200)
        for stage, headers in enumerate(stage_headers):
            if stage == 2:
                self.assertEqual(self.client.post(approval_url, json={"decision": "approve", "approved_budget": 101}, headers=headers).status_code, 400)
            response = self.client.post(approval_url, json={"decision": "approve", "note": "OK", "approved_budget": 75}, headers=headers)
            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.get_json()["status"], "approved" if stage == 2 else "review")
            if stage == 0:
                self.assertEqual(self.client.patch(endpoint, json={"data": {"reviews": {expert["user"]["id"]: review}}}, headers=expert_headers).status_code, 409)
                self.assertEqual(self.client.patch("/api/collections/users/" + stage_accounts[0]["user"]["id"], json={"data": {"approvalRoles": ["department_head", "ethics_committee"]}}, headers=admin_headers).status_code, 200)
                self.assertEqual(self.client.post(approval_url, json={"decision": "approve"}, headers={**stage_headers[0], "X-App-Role": "ethics_committee"}).status_code, 403)
            self.assertEqual(self.client.get("/api/collections/proposals", headers=headers).get_json()["docs"], [])
        events = self.client.get("/api/proposals/project/events", headers=admin_headers).get_json()["events"]
        self.assertEqual(sum(event["action"] == "approval" for event in events), 3)
        applicant_view = self.client.get("/api/collections/proposals", headers=self.headers).get_json()["docs"][0]["data"]
        self.assertEqual(applicant_view["approved_budget"], 75)
        self.assertNotIn(expert["user"]["id"], applicant_view["reviews"])
        self.assertNotIn("reviewers", applicant_view)
        self.assertEqual(applicant_view["reviews"]["1"], {"scores": review["scores"]})
        self.assertTrue(all("by" not in approval for approval in applicant_view["approvals"]))
        self.assertNotIn("by", applicant_view["decision"])

    def test_admin_can_approve_current_stage_only_once(self):
        proposal = {"title": "Project", "abstract": "Summary", "method": "Method",
                    "budget": 100, "months": 12, "outcomes": "Results", "status": "submitted"}
        self.client.put("/api/collections/proposals/project", json={"data": proposal}, headers=self.headers)
        expert = self.client.post("/api/auth/register", json={"name": "Expert", "email": "admin-review@example.com", "password": "password123"}).get_json()
        self.client.patch("/api/collections/users/" + expert["user"]["id"], json={"data": {"isReviewer": True}}, headers=self.admin_headers)
        expert_headers = {"Authorization": "Bearer " + expert["token"], "X-App-Role": "reviewer"}
        review = {"scores": {criterion: 8 for criterion in app.REVIEW_CRITERIA}, "comment": "Reviewed", "rec": "Финансировать"}
        self.client.patch("/api/collections/proposals/project", json={"data": {"reviews": {expert["user"]["id"]: review}}}, headers=expert_headers)
        approval_url = "/api/proposals/project/approval"
        approved = self.client.post(approval_url, json={"decision": "approve", "note": "Admin review"}, headers=self.admin_headers)
        self.assertEqual(approved.status_code, 200)
        self.assertEqual(approved.get_json()["status"], "review")
        proposal_data = self.client.get("/api/collections/proposals", headers=self.headers).get_json()["docs"][0]["data"]
        self.assertEqual(proposal_data["approvals"][0]["stage"], "department_head")
        self.assertEqual(self.client.post(approval_url, json={"decision": "approve"}, headers=self.admin_headers).status_code, 403)

    def test_rejection_stops_approval_workflow(self):
        proposal = {"title": "Project", "abstract": "Summary", "method": "Method",
                    "budget": 100, "months": 12, "outcomes": "Results", "status": "submitted"}
        self.client.put("/api/collections/proposals/project", json={"data": proposal}, headers=self.headers)
        expert = self.client.post("/api/auth/register", json={"name": "Expert", "email": "reject-expert@example.com", "password": "password123"}).get_json()
        self.client.patch("/api/collections/users/" + expert["user"]["id"], json={"data": {"isReviewer": True}}, headers=self.admin_headers)
        expert_headers = {"Authorization": "Bearer " + expert["token"], "X-App-Role": "reviewer"}
        review = {"scores": {criterion: 5 for criterion in app.REVIEW_CRITERIA}, "comment": "Reviewed", "rec": "Не финансировать"}
        self.client.patch("/api/collections/proposals/project", json={"data": {"reviews": {expert["user"]["id"]: review}}}, headers=expert_headers)
        head = self.client.post("/api/auth/register", json={"name": "Head", "email": "reject-head@example.com", "password": "password123"}).get_json()
        self.client.patch("/api/collections/users/" + head["user"]["id"], json={"data": {"approvalRoles": ["department_head"]}}, headers=self.admin_headers)
        head_headers = {"Authorization": "Bearer " + head["token"], "X-App-Role": "department_head"}
        url = "/api/proposals/project/approval"
        rejected = self.client.post(url, json={"decision": "reject", "note": "Not eligible"}, headers=head_headers)
        self.assertEqual(rejected.status_code, 200)
        self.assertEqual(rejected.get_json()["status"], "rejected")
        self.assertEqual(self.client.post(url, json={"decision": "approve"}, headers=head_headers).status_code, 409)
        result = self.client.get("/api/collections/proposals", headers=self.headers).get_json()["docs"][0]["data"]
        self.assertEqual(result["decision"]["note"], "Not eligible")

    def test_attachment_is_encrypted_and_access_controlled(self):
        proposal = {"title": "Project", "abstract": "Summary", "method": "Method",
                    "budget": 100, "months": 12, "outcomes": "Results", "status": "draft"}
        self.client.put("/api/collections/proposals/project", json={"data": proposal}, headers=self.headers)
        file_data = {"pid": "project", "name": "private.txt", "size": 6,
                     "data": "data:text/plain;base64,c2VjcmV0"}
        self.assertEqual(self.client.put("/api/collections/files/file1", json={"data": file_data}, headers=self.headers).status_code, 200)
        stored = app.get_document("files", "file1")["data"]
        self.assertNotIn("data", stored)
        self.assertNotIn("name", stored)
        self.assertNotIn("c2VjcmV0", stored["encrypted_payload"])
        visible = self.client.get("/api/collections/files", headers=self.headers).get_json()["docs"]
        self.assertEqual(visible[0]["data"]["name"], "private.txt")
        self.assertTrue(visible[0]["data"]["data"].endswith("c2VjcmV0"))
        stranger = self.client.post("/api/auth/register", json={"name": "Other", "email": "other@example.com", "password": "password123"}).get_json()
        other_headers = {"Authorization": "Bearer " + stranger["token"], "X-App-Role": "student"}
        self.assertEqual(self.client.get("/api/collections/files", headers=other_headers).get_json()["docs"], [])
        self.assertEqual(self.client.put("/api/collections/files/file2", json={"data": file_data}, headers=other_headers).status_code, 403)

    def test_bad_encryption_key_does_not_store_plaintext(self):
        proposal = {"title": "Private", "abstract": "Summary", "method": "Method",
                    "budget": 100, "months": 12, "outcomes": "Results", "status": "draft"}
        with patch.dict(os.environ, {"DOCUMENT_ENCRYPTION_KEY": "invalid"}):
            response = self.client.put("/api/collections/proposals/private", json={"data": proposal}, headers=self.headers)
        self.assertEqual(response.status_code, 503)
        self.assertIsNone(app.db_one("SELECT data FROM collection_documents WHERE collection = ? AND id = ?", ("proposals", "private")))
        with patch.object(app, "IS_SQLITE", False), patch.dict(os.environ, {}, clear=True):
            with self.assertRaises(app.EncryptionConfigurationError):
                app.document_cipher()

    def test_existing_unencrypted_proposal_remains_readable_and_is_encrypted_on_update(self):
        legacy = {"id": "legacy", "sid": self.student_id, "title": "Legacy project", "status": "draft", "reviews": {}}
        import json
        app.db_execute("INSERT INTO collection_documents (collection, id, data, updated) VALUES (?, ?, ?, ?)",
                       ("proposals", "legacy", json.dumps(legacy), app.now_ms()))
        self.assertEqual(self.client.get("/api/collections/proposals", headers=self.headers).get_json()["docs"][0]["data"]["title"], "Legacy project")
        self.assertEqual(self.client.patch("/api/collections/proposals/legacy", json={"data": {"title": "Updated"}}, headers=self.headers).status_code, 200)
        raw = app.db_one("SELECT data FROM collection_documents WHERE collection = ? AND id = ?", ("proposals", "legacy"))["data"]
        self.assertIn("encrypted_v1", raw)
        self.assertNotIn("Updated", raw)

    def test_faculty_can_submit_and_cannot_access_another_applicant_draft(self):
        faculty = self.client.post("/api/auth/register", json={"name": "Faculty", "email": "faculty@example.com", "password": "password123", "applicantType": "faculty"}).get_json()
        self.assertEqual(faculty["user"]["applicantType"], "faculty")
        headers = {"Authorization": "Bearer " + faculty["token"], "X-App-Role": "faculty"}
        proposal = {"title": "Research", "abstract": "Summary", "method": "Method", "outcomes": "Results", "status": "draft", "budget": 100, "months": 12}
        self.assertEqual(self.client.put("/api/collections/proposals/faculty-project", json={"data": proposal}, headers=headers).status_code, 200)
        self.assertEqual(self.client.put("/api/collections/proposals/student-project", json={"data": proposal}, headers=self.headers).status_code, 200)
        visible = self.client.get("/api/collections/proposals", headers=headers).get_json()["docs"]
        self.assertEqual([item["id"] for item in visible], ["faculty-project"])

    def test_external_reviewer_needs_permission_and_cannot_submit(self):
        external = self.client.post("/api/auth/register", json={"name": "External", "email": "external@example.com", "password": "password123", "applicantType": "external_reviewer"}).get_json()
        headers = {"Authorization": "Bearer " + external["token"], "X-App-Role": "student"}
        proposal = {"title": "Project", "abstract": "Summary", "method": "Method", "outcomes": "Results", "status": "draft", "budget": 100, "months": 12}
        self.assertEqual(self.client.put("/api/collections/proposals/external", json={"data": proposal}, headers=headers).status_code, 403)
        self.assertEqual(self.client.get("/api/collections/proposals", headers={**headers, "X-App-Role": "reviewer"}).get_json()["docs"], [])

    def test_administrator_cannot_view_or_modify_own_proposal_as_admin(self):
        applicant_headers = {**self.admin_headers, "X-App-Role": "student"}
        proposal = {"title": "Own", "abstract": "Summary", "method": "Method", "outcomes": "Results",
                    "budget": 100, "months": 12, "status": "submitted"}
        self.assertEqual(self.client.put("/api/collections/proposals/own", json={"data": proposal}, headers=applicant_headers).status_code, 200)
        self.assertEqual(self.client.get("/api/collections/proposals", headers=self.admin_headers).get_json()["docs"], [])
        self.assertEqual(self.client.patch("/api/collections/proposals/own", json={"data": {"status": "review"}}, headers=self.admin_headers).status_code, 403)
        self.assertEqual(self.client.get("/api/proposals/own/events", headers=self.admin_headers).status_code, 403)


if __name__ == "__main__":
    unittest.main()