#!/bin/bash
set -e

REPO_DIR=repo
CODENAME=stable

# Automatically pick up the latest .deb file in the current folder
PACKAGE_DEB=$(ls -t *.deb | head -n1)

echo "Using package: $PACKAGE_DEB"

# Ensure directory structure exists
mkdir -p ${REPO_DIR}/pool
mkdir -p ${REPO_DIR}/dists/${CODENAME}/main/binary-amd64
mkdir -p ${REPO_DIR}/dists/${CODENAME}/main/binary-all

# Copy the new .deb into pool
cp ${PACKAGE_DEB} ${REPO_DIR}/pool/

# Generate Packages index for amd64
apt-ftparchive packages ${REPO_DIR}/pool > ${REPO_DIR}/dists/${CODENAME}/main/binary-amd64/Packages
gzip -c ${REPO_DIR}/dists/${CODENAME}/main/binary-amd64/Packages > ${REPO_DIR}/dists/${CODENAME}/main/binary-amd64/Packages.gz

# Generate Packages index for all
apt-ftparchive packages ${REPO_DIR}/pool > ${REPO_DIR}/dists/${CODENAME}/main/binary-all/Packages
gzip -c ${REPO_DIR}/dists/${CODENAME}/main/binary-all/Packages > ${REPO_DIR}/dists/${CODENAME}/main/binary-all/Packages.gz

# Generate Release file
apt-ftparchive release ${REPO_DIR}/dists/${CODENAME} > ${REPO_DIR}/dists/${CODENAME}/Release

# Sign Release file
gpg --batch --yes --clearsign -o ${REPO_DIR}/dists/${CODENAME}/InRelease ${REPO_DIR}/dists/${CODENAME}/Release
gpg --batch --yes --armor --detach-sign -o ${REPO_DIR}/dists/${CODENAME}/Release.gpg ${REPO_DIR}/dists/${CODENAME}/Release

echo "Repo updated. Push ${REPO_DIR}/ to GitHub Pages."

