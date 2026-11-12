# GitHub setup (and a fallback)

Claude could not create the repository for you, so these are the steps to run yourself.

## 1. Create the repo and push

On github.com, create a new **empty** repository (no README, no .gitignore, no license). Then:

```bash
cd beth-risk-triage
git init -b main
git add .
git commit -m "Initial scaffold: rubric scoring pipeline, dashboard, docs"
git remote add origin https://github.com/<your-username-or-org>/beth-risk-triage.git
git push -u origin main
```

Before the first commit, check `git status` shows no `kaggle.json`, `.env`, or key files. The `.gitignore` covers them, but check anyway.

## 2. Add teammates

Repo > Settings > Collaborators > Add people. For a private repo each teammate needs a GitHub account and must accept the invite. A GitHub Organization is optional for a class project.

## 3. Set up the team workflow

- Each person: `git clone <url>`, then `pip install -e ".[dev]"` and `pytest`.
- Work on branches and open pull requests (see `CONTRIBUTING.md`).
- Optional: Repo > Settings > Branches > add a rule for `main` requiring a pull request. Availability on private repos depends on your plan, so skip it if it is not offered.
- The included GitHub Actions workflow runs the tests on every push and pull request.

## 4. If GitHub does not work

- **GitLab (gitlab.com):** closest alternative. Same git commands; swap the remote URL. Add members under Manage > Members. The GitHub Actions file will not run there; port `.github/workflows/tests.yml` to `.gitlab-ci.yml` if you want CI.
- **Bitbucket:** also works with the same git commands.
- **Avoid for code:** Google Drive or shared folders. They have no version control or review, so two people editing `rules.yaml` will overwrite each other. Drive is fine for the report and slides.

## Git basics for teammates who are new to it

```bash
git pull                          # get the latest main
git checkout -b rules/log-tamper  # new branch for your change
# ...edit, then:
pytest
git add -A && git commit -m "Describe what changed"
git push -u origin rules/log-tamper   # then open a pull request on the website
```
