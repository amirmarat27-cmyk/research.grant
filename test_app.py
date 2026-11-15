import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

os.environ["DATABASE_URL"] = "sqlite:///unused-test.db"
import app


class ProposalVersionTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.database = patch.object(app, "DATABASE_URL", "sqlite:///" + str(Path(self.directory.name) / "test.db"))
        self.database.start()
        app._database_ready = False
        self.client = app.app.test_client()
        result = self.client.post("/api/auth/register", json={
            "name": "Student", "email": "student@example.com", "password": "password123"
        }).get_json()
        self.headers = {"Authorization": "Bearer " + result["token"], "X-App-Role": "student"}

    def tearDown(self):
        self.database.stop()
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

    def test_experts_cannot_review_own_work_or_see_other_reviews(self):
        expert = self.client.post("/api/auth/register", json={
            "name": "Expert", "email": "expert@example.com", "password": "password123"
        }).get_json()
        admin_headers = {**self.headers, "X-App-Role": "admin"}
        self.assertEqual(self.client.patch(
            "/api/collections/users/" + expert["user"]["id"],
            json={"data": {"isReviewer": True}}, headers=admin_headers
        ).status_code, 200)
        expert_headers = {"Authorization": "Bearer " + expert["token"], "X-App-Role": "reviewer"}
        proposal = {"title": "Project", "abstract": "Summary", "method": "Method",
                    "budget": 100, "months": 12, "outcomes": "Results", "status": "submitted"}
        self.assertEqual(self.client.put("/api/collections/proposals/project", json={"data": proposal}, headers=self.headers).status_code, 200)
        review = {"scores": {"Originality": 8}, "comment": "Confidential"}
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
        admin_headers = {**self.headers, "X-App-Role": "admin"}
        milestone = {"title": "First payment", "amount": 80, "due_date": "2026-12-01",
                     "report_due": "2026-12-20", "status": "planned"}
        endpoint = "/api/collections/proposals/project"
        self.assertEqual(self.client.patch(endpoint, json={"data": {"milestones": [milestone]}}, headers=admin_headers).status_code, 400)
        self.assertEqual(self.client.patch(endpoint, json={"data": {"status": "approved"}}, headers=admin_headers).status_code, 200)
        self.assertEqual(self.client.patch(endpoint, json={"data": {"milestones": [milestone]}}, headers=admin_headers).status_code, 200)
        self.assertEqual(self.client.patch(endpoint, json={"data": {"milestones": [milestone, milestone]}}, headers=admin_headers).status_code, 400)
        self.assertEqual(self.client.patch(endpoint, json={"data": {"milestones": [milestone]}}, headers=self.headers).status_code, 403)
        events = self.client.get("/api/proposals/project/events", headers=admin_headers).get_json()["events"]
        self.assertTrue(any("milestones" in event["details"] for event in events))


if __name__ == "__main__":
    unittest.main()