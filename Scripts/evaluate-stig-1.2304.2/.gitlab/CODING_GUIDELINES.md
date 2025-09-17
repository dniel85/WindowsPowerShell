# Coding Guidelines for Evaluate-STIG

## Coding Style

* We recommend, but do NOT require utilizing the multi-platform [Visual Studio Code (VS Code)](https://code.visualstudio.com/). Ensure to check your local guidance prior to utilizing it.
* Evaluate-STIG utilizes [Stroustrup Indentation Style](https://en.wikipedia.org/wiki/Indentation_style#Variant:_Stroustrup)
* We are adopting and following the [PoshCode - PowerShell Practice and Style Guide](https://github.com/PoshCode/PowerShellPracticeAndStyle/blob/master/Style-Guide/Code-Layout-and-Formatting.md) when possible. 

## Commit Messages

The blog post, [A Note About Git Commit Messages](https://tbaggery.com/2008/04/19/a-note-about-git-commit-messages.html), from Tim Pope and this other blog post, [How to Write a Git Commit Message](https://chris.beams.io/posts/git-commit/), by Chris Beams are fantastic primers on writing a git commit message and should be followed. They can be summarized as:
* Separate subject from body with a blank line
* Limit subject line to 50 characters
* Capitalize subject line
* Do NOT end the subject line with a period
* Use the imperative (command) mood in the subject line
* Wrap the body at 72 characters
* Use the body to explain WHAT and WHY instead of how

A self-aware example of this is below:
```bash
    (ES-1234) Make the example in CODING_GUIDELINES.md imperative and concrete

    Without this patch applied the example commit message in the 
    CODING_GUIDELINES.md document is not a concrete example. This is a problem
    because the contributor is left to imagine what the commit message should 
    look like based on a description rather than an example. This patch fixes
    the problem by making the example concrete and imperative.

    The first line is a real-life imperative statement with a ticket number
    from our issue tracker. The body describes the behavior without the patch,
    why this is a problem, and how the patch fixes the problem when applied.
```

## Branches

Future information on branches is being developed.
