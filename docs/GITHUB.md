# Publishing this project on GitHub

This page explains what GitHub is used for here, how the public copy of the project is produced, and the commands to
upload it the first time and to update it later.

## What GitHub gives the project

| Function | What it means for this project |
|---|---|
| **Version history** | Every change is a commit: who changed what, when and why. Any earlier version can be looked at or restored. |
| **Off-site backup** | The code lives on GitHub as well as on the developer laptop and the server. |
| **Sharing** | Colleagues (or anyone, for a public repository) can read the code, the README and the documentation in the browser. |
| **Collaboration** | Others work on a *branch* and propose changes with a *pull request*; changes are reviewed before they are merged. |
| **Issues** | Bugs and ideas are tracked as issues, linked to the commits that fix them. |
| **GitHub Actions** | Optional: the tests (`python -m unittest ...`) can run automatically on every push. |
| **Releases / tags** | A version that was deployed can be tagged (for example `v2026.10.23`) and downloaded as an archive. |

## How the public copy is produced

The working copy of the project contains real infrastructure details (addresses, host names, user names) in its
deploy scripts, examples and tests. The repository on GitHub is therefore a **sanitized copy**, built by a private
export tool that is kept out of the repository:

1. Only the source is copied: `portal/`, `tools/`, `docs/`, `bastion/`. Not copied: virtualenvs, Python wheels,
   databases, build archives, reports, work-instruction documents, runtime data, keys and certificates.
2. Company, product, customer and site names, internal domains, user names and ports are replaced with neutral examples.
3. Every IPv4 address is replaced with an example address **of the same kind** (a private address stays private, a
   public one stays public) and the same address is replaced the same way everywhere, so subnet relations are kept and
   the tests still pass.
4. `README.md`, this page and `.gitignore` are added.
5. The result is scanned. The export stops, naming the file and line, when anything identifying is left: a name, an
   original address, or key material (private keys, cloud or GitHub tokens).
6. The tests are run on the copy before it is committed.

Rules for everyone who commits to this repository:
- Never commit real addresses, host names, passwords, tokens, keys, certificates, databases or customer data.
- Configuration with real values stays in files that `.gitignore` excludes (`sites.yml`, `auth.yml`, `*.env` outside
  `portal/deploy/`, `*.key`, `*.pem`).
- If a secret was pushed by mistake, treat it as leaked: change it at its source first, then remove it from the
  history (deleting the file in a new commit is not enough).

## First upload

1. On <https://github.com>, signed in: **New repository** → a name (for example `ops-portal`) → **Public** →
   do **not** add a README, .gitignore or license (they come from the export) → **Create repository**.
2. In the export folder:

   ```bash
   git init -b main
   git add -A
   git commit -m "Initial import"
   git remote add origin https://github.com/<account>/<repository>.git
   git push -u origin main
   ```

3. Signing in from the command line: GitHub does not accept the account password for `git push`. Use one of:
   - **GitHub CLI**: `brew install gh`, then `gh auth login` (choose GitHub.com, HTTPS, login with a web browser) —
     git then uses that login;
   - a **personal access token** (Settings → Developer settings → Personal access tokens → *Fine-grained*, access to
     this repository, *Contents: Read and write*), entered as the password when `git push` asks; macOS keeps it in the
     keychain;
   - an **SSH key** added on GitHub (Settings → SSH and GPG keys), with the remote `git@github.com:<account>/<repository>.git`.

## Updating the repository

After changes in the working copy:

1. Run the export tool again (it rebuilds the copy and keeps its `.git` folder) and check that its scan reports no
   problem.
2. Run the tests in the copy.
3. Review and push:

   ```bash
   git status                 # what changed
   git diff                   # the changes themselves
   git add -A
   git commit -m "VyOS upgrade: grow the disk partition when the image store is too small"
   git push
   ```

Write commit messages that say what changed and why; they are the history of the project.

## Working with others

```bash
git switch -c feature/my-change      # a branch for one change
# edit, test, commit
git push -u origin feature/my-change # then open a pull request on GitHub
```

The pull request shows the changes, runs the checks (when GitHub Actions is set up) and is merged into `main` after
review. Keep `main` deployable.

## License

The repository has no license file yet. Without one, others may read the code but have no right to reuse it. Add a
`LICENSE` (for example MIT or Apache-2.0) if reuse should be allowed.
