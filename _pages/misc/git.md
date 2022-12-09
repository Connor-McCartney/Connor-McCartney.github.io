

Basics of using github/git


# Github access token

Settings > Developer Settings > Personal Access Tokens > Tokens (Classic) > Generate new token

Copy this to your password manager.


# Common commands

git clone <URL>
  
git status
  
git add [example.file or folder]
  
git commit -m "message"  # This will commit the changes locally
  
git push  # Enter your username and then the access token instead of your password

  
# Branches
  
git branch  # lists branches with asterisk next to current branch
  
git branch [branch-name]  # creates new branch
  
git checkout [branch-name]  # switches branch
  
git branch -d [branch-name]  # deletes branch
  
git merge [branch-name]  # merges this branch into your current active branch
  
git rebase [branch-name]  # rebases your current active branch on top of the given branch. Never rebase commits that others are using!
