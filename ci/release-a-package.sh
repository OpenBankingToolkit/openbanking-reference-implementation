#!/usr/bin/env bash
set -e

if [ -z "$GITHUB_GPG_KEY_ID" ]; then
    echo "GITHUB_GPG_KEY_ID is not set"
    exit 1
fi

if [ -z "$RELEASE_NAME" ]; then
    echo "RELEASE_NAME is not set"
    exit 1
fi

if [ -z "$GITHUB_USERNAME" ]; then
    echo "GITHUB_USERNAME is not set"
    exit 1
fi

if [ -z "$GITHUB_ACCESS_TOKEN" ]; then
    echo "GITHUB_ACCESS_TOKEN is not set"
    exit 1
fi

if [ -z "$CF_BRANCH" ]; then
    echo "CF_BRANCH is not set"
    exit 1
fi

echo "Setting global git user config"
git config --global user.email "openbankbot@forgerock.com";
git config --global user.name "openbankbot";

echo "Setting global git signing"
git config --global commit.gpgsign true
git config --global user.signingkey $GITHUB_GPG_KEY_ID
echo "GITHUB_GPG_KEY_ID = $GITHUB_GPG_KEY_ID"

echo "Adding github gpg key to gpg"
echo  "$GITHUB_GPG_KEY" | base64 -d > private.key
gpg --import ./private.key
rm ./private.key

pushd /codefresh/volume/$1

echo "setting $2/package.json project_version to $RELEASE_NAME"
sed -i "/\"project_version\"/c\  \"project_version\":\"$RELEASE_NAME\",\ " $2/package.json
git add .
echo "Git status:"
echo `git status`
if git diff-index --quiet HEAD --; then
  echo "Nothing to commit"
else
    git commit -m "Set package version for release $RELEASE_NAME"
    echo "Pushing changes: git push https://github.com/ForgeCloud/$1.git $CF_BRANCH"
    echo `git push https://$GITHUB_USERNAME:$GITHUB_ACCESS_TOKEN@github.com/ForgeCloud/$1.git $CF_BRANCH`
    rev=`git rev-parse HEAD`
    echo "Tagging $1's $rev as $RELEASE_NAME"
    git tag -a $RELEASE_NAME -m "RELEASE_NAME" $rev
    echo "pushing tag $RELEASE_NAME to $1"
    git push https://$GITHUB_USERNAME:$GITHUB_ACCESS_TOKEN@github.com/ForgeCloud/$1.git $CF_BRANCH $RELEASE_NAME
fi


popd