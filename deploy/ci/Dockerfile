# CI tools image for the Debuglet kernel and installed-package lanes.
#
# The image adds the Debian packages listed in packages.txt to the pinned Go
# base image so that those lanes install nothing at job runtime. Every input is
# pinned: the base image by manifest digest, the Debian archive by snapshot
# timestamp, and each package by exact version. A version that the snapshot no
# longer offers fails the build instead of resolving to a different one.
#
# Build and update: docs/ci-images.md.

ARG BASE_IMAGE=golang:1.25.11-bookworm
ARG BASE_DIGEST=sha256:b96f24a8d7d010ea0acb9c3ba99064740f02b6b984612b28bd3c9c5ab9453e38
FROM ${BASE_IMAGE}@${BASE_DIGEST}

ARG BASE_IMAGE
ARG BASE_DIGEST
ARG DEBIAN_SNAPSHOT=20260623T000000Z
ARG TOOLS_IMAGE=debuglet-ci-tools:20260623-1

COPY packages.txt /etc/debuglet-ci/packages.txt

# Resolve packages from the frozen snapshot the base image was built from, so
# repeating this build selects the same archive contents. The snapshot sources
# stay in place: an unexpected apt call in a job cannot reach a moving mirror.
RUN set -eu; \
    { \
      echo 'Types: deb'; \
      echo "URIs: http://snapshot.debian.org/archive/debian/${DEBIAN_SNAPSHOT}"; \
      echo 'Suites: bookworm bookworm-updates'; \
      echo 'Components: main'; \
      echo 'Signed-By: /usr/share/keyrings/debian-archive-keyring.gpg'; \
      echo; \
      echo 'Types: deb'; \
      echo "URIs: http://snapshot.debian.org/archive/debian-security/${DEBIAN_SNAPSHOT}"; \
      echo 'Suites: bookworm-security'; \
      echo 'Components: main'; \
      echo 'Signed-By: /usr/share/keyrings/debian-archive-keyring.gpg'; \
    } > /etc/apt/sources.list.d/debian.sources; \
    echo 'Acquire::Check-Valid-Until "false";' > /etc/apt/apt.conf.d/10debuglet-snapshot; \
    sed -e 's/#.*//' /etc/debuglet-ci/packages.txt \
      | awk 'NF == 2 { print $1 " " $2 }' | LC_ALL=C sort > /etc/debuglet-ci/pins.txt; \
    [ -s /etc/debuglet-ci/pins.txt ]; \
    awk '{ print $1 "=" $2 }' /etc/debuglet-ci/pins.txt > /tmp/apt-pins; \
    apt-get update; \
    xargs -a /tmp/apt-pins apt-get install -y --no-install-recommends; \
    rm -f /tmp/apt-pins; \
    rm -rf /var/lib/apt/lists/*

# Fail the build rather than ship an image whose packages differ from the pins,
# and record what was installed so a job can re-check it without a network.
RUN set -eu; \
    : > /etc/debuglet-ci/installed.txt; \
    while read -r name version; do \
      got="$(dpkg-query -W -f='${Version}' "$name")"; \
      if [ "$got" != "$version" ]; then \
        echo "pinned $name $version but installed $got" >&2; \
        exit 1; \
      fi; \
      echo "$name $got" >> /etc/debuglet-ci/installed.txt; \
    done < /etc/debuglet-ci/pins.txt; \
    sha256sum < /etc/debuglet-ci/pins.txt | cut -d' ' -f1 > /etc/debuglet-ci/toolchain.sha256; \
    { \
      echo "DEBUGLET_CI_TOOLS_IMAGE=${TOOLS_IMAGE}"; \
      echo "DEBUGLET_CI_BASE_IMAGE=${BASE_IMAGE}"; \
      echo "DEBUGLET_CI_BASE_DIGEST=${BASE_DIGEST}"; \
      echo "DEBUGLET_CI_DEBIAN_SNAPSHOT=${DEBIAN_SNAPSHOT}"; \
    } > /etc/debuglet-ci/image.env; \
    { \
      go version; \
      gcc --version | head -n 1; \
      clang --version | head -n 1; \
      llvm-strip --version | head -n 1; \
      python3 --version; \
    } > /etc/debuglet-ci/tools.txt; \
    cat /etc/debuglet-ci/image.env /etc/debuglet-ci/tools.txt; \
    cat /etc/debuglet-ci/toolchain.sha256
