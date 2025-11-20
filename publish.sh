#!/bin/bash
set -e

# Adjust these variables to your project
REPO_DIR=repo
CODENAME=stable
PACKAGE_DEB=snap_connection_manager_1.2.1.deb

# Ensure directory structure exists
mkdir -p ${REPO_DIR}/pool
mkdir -p ${REPO_DIR}/dists/${CODENAME}/main/binary-amd64

# Copy the new .deb into pool
cp ${PACKAGE_DEB} ${REPO_DIR}/pool/

# Generate Packages index
apt-ftparchive packages ${REPO_DIR}/pool > ${REPO_DIR}/dists/${CODENAME}/main/binary-amd64/Packages
gzip -c ${REPO_DIR}/dists/${CODENAME}/main/binary-amd64/Packages > ${REPO_DIR}/dists/${CODENAME}/main/binary-amd64/Packages.gz

# Generate Release file
apt-ftparchive release ${REPO_DIR}/dists/${CODENAME} > ${REPO_DIR}/dists/${CODENAME}/Release

# Sign Release file
gpg --batch --yes --clearsign -o ${REPO_DIR}/dists/${CODENAME}/InRelease ${REPO_DIR}/dists/${CODENAME}/Release
gpg --batch --yes --armor --detach-sign -o ${REPO_DIR}/dists/${CODENAME}/Release.gpg ${REPO_DIR}/dists/${CODENAME}/Release

echo "Repo updated. Push ${REPO_DIR}/ to GitHub Pages."

