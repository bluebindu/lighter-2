FROM debian:buster-slim

ENV APP_DIR="/srv/app" L_DIR="lighter_bitcoin" USER="lighter"
ENV LANG="C.UTF-8" PYTHONUNBUFFERED=1 PYTHONIOENCODING="UTF-8"

RUN adduser --home $APP_DIR --shell /bin/bash --disabled-login \
        --gecos "$USER user" $USER \
    && mkdir -p $APP_DIR/$L_DIR

COPY unix_helper.sh /srv/app/
RUN apt-get update \
    && apt-get -y install --no-install-recommends \
        bash-completion gosu libscrypt0 python3-pip \
    && host_tag_arch=$(/srv/app/unix_helper.sh get_host_tag_arch) \
    && if [ "$host_tag_arch" = "arm32v7" ]; then \
            apt-get update \
            && apt-get -y install g++ libffi-dev python3-dev \
            && apt-get clean \
            && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*; \
        fi \
    && apt-get clean && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

WORKDIR $APP_DIR

COPY $L_DIR/__init__.py $L_DIR/settings.py $L_DIR/
COPY $L_DIR/db.py $L_DIR/lighter.py $L_DIR/macaroons.py $L_DIR/
COPY $L_DIR/migrate.py $L_DIR/errors.py $L_DIR/
COPY $L_DIR/lighter.proto $L_DIR/light_*.py $L_DIR/
COPY $L_DIR/cliter.py $L_DIR/secure.py $L_DIR/pairing.py $L_DIR/
COPY $L_DIR/utils $L_DIR/utils
COPY $L_DIR/migrations $L_DIR/migrations
COPY AUTHORS.md CHANGELOG.md CONTRIBUTING.md LICENSE.md README.md ./
COPY MANIFEST.in setup.py ./
COPY doc doc
COPY examples/config.sample examples/

# Install Lighter on user's PATH
RUN chown -R $USER /srv/app
ARG DEVELOPMENT
ENV DEVELOPMENT=$DEVELOPMENT OPTS="--user --no-warn-script-location"
USER $USER
RUN mkdir -p ~/.local/share/bash-completion/completions/ \
    && python3 -m pip install $OPTS --upgrade setuptools wheel \
    && if [ "$DEVELOPMENT" = '1' ]; then \
           echo "Development mode ON" \
           && python3 -m pip install $OPTS --editable . \
           && python3 -m pip install $OPTS pycodestyle pylint pytest pytest-cov \
           && cp ~/examples/complete-cliter-bash.sh \
                 ~/.local/share/bash-completion/completions/cliter ; \
       else \
           python3 -m pip install $OPTS . \
           && cp ~/.local/share/doc/lighter_bitcoin/examples/complete-cliter-bash.sh \
                 ~/.local/share/bash-completion/completions/cliter ; \
       fi \
    && echo 'PATH="$PATH:$APP_DIR/.local/bin"' >> $HOME/.bashrc

USER root

COPY docker/start-lighter.sh /usr/local/bin/
RUN chmod +x /usr/local/bin/start-lighter.sh

VOLUME $APP_DIR/.lighter/logs/
EXPOSE 1708
ENTRYPOINT ["/usr/local/bin/start-lighter.sh"]
