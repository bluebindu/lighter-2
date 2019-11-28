FROM debian:buster-slim

RUN apt-get update && \
    apt-get -y install --no-install-recommends \
    curl gosu jq libscrypt0 make python3-pip unzip virtualenv && \
    apt-get clean && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

ARG VERSION
ENV APP_DIR="/srv/app" ENV="/srv/env" VERSION=$VERSION
ENV L_DIR="lighter" USER="lighter"
ENV LANG="C.UTF-8" PYTHONUNBUFFERED=1 PYTHONIOENCODING="UTF-8"

RUN adduser --home $APP_DIR --shell /bin/bash --disabled-login \
    --gecos "$USER user" $USER && \
    mkdir -p $APP_DIR/$L_DIR

WORKDIR $APP_DIR

COPY Makefile unix_make.sh ./

RUN mkdir -p lighter-data/certs lighter-data/logs && \
    touch lighter-data/config && make check

RUN host_tag_arch=$(./unix_make.sh get_host_tag_arch) \
    && if [ "$host_tag_arch" = "arm32v7" ]; then \
            apt-get update \
            && apt-get -y install g++ libffi-dev python3-dev \
            && apt-get clean \
            && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*; \
        fi \
    && make setup

COPY lighter/lighter.proto $L_DIR

# Install Lighter for all implementations
RUN make build

COPY docker/start-lighter.sh /usr/local/bin/
RUN chmod +x /usr/local/bin/start-lighter.sh

RUN mkdir -p $APP_DIR/lighter-data/db $APP_DIR/lighter-data/macaroons

COPY cliter.py setup.py ./
COPY lighter/__init__.py lighter/settings.py $L_DIR/

# Install Cliter on user's PATH
RUN chown -R $USER /srv/env /srv/app
ARG DEVELOPMENT
ENV DEVELOPMENT=$DEVELOPMENT
USER $USER
RUN pip3 install --user --upgrade setuptools wheel \
    && if [ "$DEVELOPMENT" = '1' ]; then \
        echo "Development mode ON" && pip3 install --user --editable .; \
    else pip3 install --user .; fi \
    && echo 'PATH="$PATH:$APP_DIR/.local/bin"' >> $HOME/.bashrc \
    && echo 'eval "$(_CLITER_COMPLETE=source cliter)"' >> $HOME/.bashrc

COPY main.py secure.py migrate.py ./
COPY migrations migrations
COPY lighter/db.py lighter/lighter.py lighter/macaroons.py $L_DIR/
COPY lighter/utils.py lighter/errors.py lighter/light_* $L_DIR/

USER root
VOLUME $APP_DIR/lighter-data/logs/
EXPOSE 1708
ENTRYPOINT ["/usr/local/bin/start-lighter.sh"]
