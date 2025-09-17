# Contributing to Evaluate-STIG

We welcome and appreciate contributions from the community. There are many ways to become involved with the Evaluate-STIG project. Some examples include:
* [Filing bug reports](#bugs)
* Joining one of our chatrooms to discuss Evaluate-STIG
* Writing/Improving documentation
* Contributing code

Continue reading on to ensure a smooth contribution process.

## Table of Contents

* [Submitting an Issue](#submit-issue)
    * [Submitting a bug report](#bugs)
    * [Submitting a feature request](#features)
    * [Submitting a pull request](#pull-requests)
* [Resources for utilizing GIT and SPORK](#git-spork-resources)
* [Coding Guidelines](#coding-guidelines)
* [Sample Git Workflow](#sample-git-workflow)

<a name="submit-issue"></a>

## Submitting an Issue

The issue tracker is the preferred channel for [bug reports](#bugs), [feature requests](#features) and [submitting pull requests](#pull-requests), but please respect the following restrictions:

* Please **do not** use the issue tracker for personal support requests. Utilize one of the many ways to [contact us](https://wiki.navsea.navy.mil/x/s4LZE)
* Please **do not** derail or troll issues. Keep the discussion on topic and respect the opinions of others.

<a name="bugs"></a>
## Bug Reports

A bug is a _demonstrable problem_ that is caused by the code in the repository. Good bug reports are extremely helpful - thank you!

Guidelines for bug reports:

1. **Use the SPORK issue search** &mdash; check if the issue has already been reported.

2. **Check if the issue has been fixed** &mdash; try to reproduce it using the latest `master` or development branch in the repository.

A good bug report shouldn't leave others needing to chase you up for more information. Please try to be as detailed as possible in your report. What is your environment? What steps will reproduce the issue? What version of PowerShell and OS experience the problem? What would you expect to be the outcome? All these details will help people to fix any potential bugs.

Example:

> Short and descriptive example bug report title
>
> A summary of the issue and the PowerShell/OS environment in which it occurs. If suitable, include the steps required to reproduce the bug.
>
> 1. This is the first step
> 2. This is the second step
> 3. Further steps, etc.
>
> Any other information you want to share that is relevant to the issue being reported. This might include the lines of code that you have identified as causing the bug, and potential solutions (and your opinions on their merits).

<a name="features"></a>
## Feature Request
Feature requests are welcome. But take a moment to find out whether your idea fits with the scope and aims of the project. It's up to *you* to make a strong case to convince the project's developers of the merits of this feature. Please provide as much detail and context as possible.

<a name="pull-requests"></a>
## Pull requests

Good pull requests - patches, improvements, new features - are a fantastic help. They should remain focused in scope and avoid containing unrelated commits.

**Please ask first** before embarking on any significant pull request (e.g. implementing features, refactoring code, porting to a different language), otherwise you risk spending a lot of time working on something that the project's developers might not want to merge into the project.

Please adhere to the coding conventions used throughout a project (indentation, accurate comments, etc.) and any other requirements (such as test coverage).

<a name="git-spork-resources"></a>
## Resources for utilizing GIT and SPORK
* Ensure you have a [Fusion Account](https://spork.navsea.navy.mil/) to utilize SPORK
* Resources for Fusion's Gitlab instance, SPORK can be found on the [SPORK Wiki Page](https://wiki.navsea.navy.mil/display/SPORK)

## Coding Guidelines
Please review our [Coding Guidelines](./.gitlab/CODING_GUIDELINES.md) if you intend to contribute to the project. Some topics covered include:
* Code Styling and Formatting
* Commit Message guidelines
* Branch Names

* We recommend utilizing the multi-platform [Visual Studio Code (VS Code)](https://code.visualstudio.com/) but do not require it. Ensure to check your local guidance prior to utilizing it.
* Evaluate-STIG utilizes [Stroustrup Indentation Style](https://en.wikipedia.org/wiki/Indentation_style#Variant:_Stroustrup)
* Spaces surrounding Braces, Pipes, Separators, Parenthesis, etc
* No aliases
* Powershell-related files encoded in UTF8 for Code Signing
* Adhere to these [git commit message guidelines](http://tbaggery.com/2008/04/19/a-note-about-git-commit-messages.html)
* Feel free to ask us for our Evaluate-STIG VS Code Workspace settings.json.

<a name="sample-workflow"></a>
## Sample Git Workflow
Follow this process if you'd like your work considered for inclusion in the project:

1. [Fork](https://docs.gitlab.com/ee////user/project/working_with_projects.html) the project, clone your fork,
   and configure the remotes:

   ```bash
   # Clone your fork of the repo into the current directory
   git clone https://spork.navsea.navy.mil/nswc-crane-division/evaluate-stig.git
   # Navigate to the newly cloned directory
   cd <repo-name>
   # Assign the original repo to a remote called "upstream"
   git remote add upstream https://spork.navsea.navy.mil/nswc-crane-division/evaluate-stig.git
   # Shows Origin (your fork) and upstream (source repo)
   git remote -v
   ```

2. If you cloned a while ago, get the latest changes from upstream:

   ```bash
   git checkout <dev-branch>
   git pull upstream <dev-branch>
   ```

3. Create a new topic branch (off the main project development branch) to
   contain your feature, change, or fix:

   ```bash
   git checkout -b <topic-branch-name>
   ```

4. Commit your changes in logical chunks. Use Git's [interactive rebase](https://docs.gitlab.com/ee/topics/git/git_rebase.html#interactive-rebase) feature to tidy up your commits before making them public. A sample of this step would look like:
    ```bash
    # Shows any modified files in your local repo. Handle these prior to making further code changes
    git status
    <Code changes>
    # Add new files to the branch to be tracked
    git add
    # Commit the new files added to branch so they are maintained in that branch.
    git commit -a -m "Optimize code by replacing arrays with generic lists where applicable"
    ```

5. Locally merge (or rebase) the upstream development branch into your topic branch:

   ```bash
   # Fetch Upstream. This is the metadata of what changed.
   git fetch upstream
   # Ensure you are on your master branch (or whatever branch you intend to pull the upstream branch from)
   git checkout master
   # Merge upstream master into local master
   git merge upstream/master
   ```



6. Push your topic branch up to your fork:

   ```bash
   git push origin <topic-branch-name>
   ```

7. [Open a Pull Request](https://docs.gitlab.com/ee/user/project/merge_requests/creating_merge_requests.html) with a clear title and description.


**IMPORTANT**: By submitting a patch, you agree to allow the project owner to
license your work under the same license as that used by the project.