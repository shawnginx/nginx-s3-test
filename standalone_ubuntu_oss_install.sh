#!/usr/bin/env bash

LAMBDA_SERVER=lambda.us-east-2.amazonaws.com
LAMBDA_REGION=us-east-2
LAMBDA_SERVER_PROTO=https

S3_BUCKET_NAME=nginx-0206
S3_SERVER=s3-us-east-2.amazonaws.com
S3_SERVER_PORT=443
S3_SERVER_PROTO=https
S3_REGION=us-east-2
S3_STYLE=virtual
AWS_DEBUG=true
AWS_SIGS_VERSION=4
ALLOW_DIRECTORY_LIST=true
PROVIDE_INDEX_PAGE=true
APPEND_SLASH_FOR_POSSIBLE_DIRECTORY=false
PROXY_CACHE_VALID_OK=1h
PROXY_CACHE_VALID_NOTFOUND=1m
PROXY_CACHE_VALID_FORBIDDEN=30s
CORS_ENABLED=false
DNS_RESOLVERS=8.8.8.8

set -o errexit   # abort on nonzero exit status
set -o pipefail  # don't hide errors within pipes

if [ "$EUID" -ne 0 ];then
  >&2 echo "This script requires root level access to run"
  exit 1
fi

if ! dpkg --status grep 2>/dev/null | grep --quiet Status > /dev/null; then
  >&2 echo "This script requires the grep package to be installed in order to run"
  exit 1
fi

if ! dpkg --status coreutils 2>/dev/null | grep --quiet Status > /dev/null; then
  >&2 echo "This script requires the coreutils package to be installed in order to run"
  exit 1
fi

if ! dpkg --status apt 2>/dev/null | grep --quiet Status > /dev/null; then
  >&2 echo "This script requires the apt package to be installed in order to run"
  exit 1
fi

if ! dpkg --status wget 2>/dev/null | grep --quiet Status > /dev/null; then
  >&2 echo "This script requires the wget package to be installed in order to run"
  exit 1
fi

failed=0

required=("S3_BUCKET_NAME" "S3_SERVER" "S3_SERVER_PORT" "S3_SERVER_PROTO"
"S3_REGION" "S3_STYLE" "ALLOW_DIRECTORY_LIST" "AWS_SIGS_VERSION" "LAMBDA_SERVER" "LAMBDA_REGION")

if [ ! -z ${AWS_CONTAINER_CREDENTIALS_RELATIVE_URI+x} ]; then
  echo "Running inside an ECS task, using container credentials"
  uses_iam_creds=1
elif curl --output /dev/null --silent --head --fail --connect-timeout 2 "http://169.254.169.254"; then
  echo "Running inside an EC2 instance, using IMDS for credentials"
  uses_iam_creds=1
else
  required+=("AWS_ACCESS_KEY_ID" "AWS_SECRET_ACCESS_KEY")
  uses_iam_creds=0
fi

for name in ${required[@]}; do
  if [ -z ${!name+x} ]; then
      >&2 echo "Required ${name} environment variable missing"
      failed=1
  fi
done

if [ "${S3_SERVER_PROTO}" != "http" ] && [ "${S3_SERVER_PROTO}" != "https" ]; then
    >&2 echo "S3_SERVER_PROTO contains an invalid value (${S3_SERVER_PROTO}). Valid values: http, https"
    failed=1
fi

if [ "${AWS_SIGS_VERSION}" != "2" ] && [ "${AWS_SIGS_VERSION}" != "4" ]; then
  >&2 echo "AWS_SIGS_VERSION contains an invalid value (${AWS_SIGS_VERSION}). Valid values: 2, 4"
  failed=1
fi

if [ $failed -gt 0 ]; then
  exit 1
fi

if [ "${1}" == "" ]; then
  branch="master"
else
  branch="${1}"
fi
echo "Installing using github '${branch}' branch"


echo "S3 Backend Environment"
echo "Access Key ID: ${AWS_ACCESS_KEY_ID}"
echo "Origin: ${S3_SERVER_PROTO}://${S3_BUCKET_NAME}.${S3_SERVER}:${S3_SERVER_PORT}"
echo "Region: ${S3_REGION}"
echo "Addressing Style: ${S3_STYLE}"
echo "AWS Signatures Version: v${AWS_SIGS_VERSION}"
echo "DNS Resolvers: ${DNS_RESOLVERS}"
echo "Directory Listing Enabled: ${ALLOW_DIRECTORY_LIST}"

set -o nounset   # abort on unbound variable

if [ ! -f /etc/apt/sources.list.d/nginx.list ]; then
  release="$(grep 'VERSION_CODENAME' /etc/os-release | cut --delimiter='=' --field=2)"
  echo "▶ Adding NGINX package repository"

  cat > "/etc/apt/sources.list.d/nginx.list" << EOF
deb https://nginx.org/packages/ubuntu/ $release nginx
deb-src https://nginx.org/packages/ubuntu/ $release nginx
EOF

  key="ABF5BD827BD9BF62"
  apt-key adv --keyserver keyserver.ubuntu.com --recv-keys $key
  apt-get -qq update
fi

to_install=""

if ! dpkg --status nginx 2>/dev/null | grep --quiet Status > /dev/null; then
  to_install="nginx"
fi

if ! dpkg --status nginx-module-njs 2>/dev/null | grep --quiet Status > /dev/null; then
  # find latest njs version because the package manager gets this wrong
  latest_njs_version="$(apt show -a nginx-module-njs 2>/dev/null | grep 'Version:' | cut --delimiter=' ' --field=2 | sort --reverse | head --lines=1)"
  to_install="${to_install} nginx-module-njs=${latest_njs_version}"
fi

if ! dpkg --status nginx-module-xslt 2>/dev/null | grep --quiet Status > /dev/null; then
  to_install="${to_install} nginx-module-xslt"
fi


if [ "${to_install}" != "" ]; then
  apt-get -qq install --yes ${to_install}
  echo "▶ Stopping nginx so that it can be configured as a S3 Gateway"
  systemctl stop nginx
fi

echo "▶ Adding environment variables to NGINX configuration file: /etc/nginx/environment"
cat > "/etc/nginx/environment" << EOF
# Enables or disables directory listing for the S3 Gateway (1=enabled, 0=disabled)
ALLOW_DIRECTORY_LIST=${ALLOW_DIRECTORY_LIST}
# AWS Authentication signature version (2=v2 authentication, 4=v4 authentication)
AWS_SIGS_VERSION=${AWS_SIGS_VERSION}
# Name of S3 bucket to proxy requests to
S3_BUCKET_NAME=${S3_BUCKET_NAME}
# Region associated with API
S3_REGION=${S3_REGION}
# SSL/TLS port to connect to
S3_SERVER_PORT=${S3_SERVER_PORT}
# Protocol to used connect to S3 server - 'http' or 'https'
S3_SERVER_PROTO=${S3_SERVER_PROTO}
# S3 host to connect to
S3_SERVER=${S3_SERVER}
# The S3 host/path method - 'virtual', 'path' or 'default'
S3_STYLE=${S3_STYLE}
# Flag (true/false) enabling AWS signatures debug output (default: false)
AWS_DEBUG=${AWS_DEBUG}
PROXY_CACHE_VALID_OK=${PROXY_CACHE_VALID_OK}
PROXY_CACHE_VALID_NOTFOUND=${PROXY_CACHE_VALID_NOTFOUND}
PROXY_CACHE_VALID_FORBIDDEN=${PROXY_CACHE_VALID_FORBIDDEN}
CORS_ENABLED=${CORS_ENABLED}
LAMBDA_SERVER=${LAMBDA_SERVER}
LAMBDA_REGION=${LAMBDA_REGION}
EOF

# By enabling CORS, we also need to enable the OPTIONS method which
# is not normally used as part of the gateway. The following variable
# defines the set of acceptable headers.
if [ "${CORS_ENABLED}" == "1" ]; then
    cat >> "/etc/nginx/environment" << EOF
LIMIT_METHODS_TO="GET HEAD OPTIONS"
LIMIT_METHODS_TO_CSV="GET, HEAD, OPTIONS"
EOF
else
    cat >> "/etc/nginx/environment" << EOF
LIMIT_METHODS_TO="GET HEAD"
LIMIT_METHODS_TO_CSV="GET, HEAD"
EOF
fi

if [ -z "${CORS_ALLOWED_ORIGIN+x}" ]; then
CORS_ALLOWED_ORIGIN="*"
fi

# Only include these env vars if we are not using a instance profile credential
# to obtain S3 permissions.
if [ $uses_iam_creds -eq 0 ]; then
  cat >> "/etc/nginx/environment" << EOF
# AWS Access key
AWS_ACCESS_KEY_ID=${AWS_ACCESS_KEY_ID}
# AWS Secret access key
AWS_SECRET_ACCESS_KEY=${AWS_SECRET_ACCESS_KEY}
EOF
fi

set +o nounset   # don't abort on unbound variable
if [ -z ${DNS_RESOLVERS+x} ]; then
  cat >> "/etc/default/nginx" << EOF
# DNS resolvers (separated by single spaces) to configure NGINX with
DNS_RESOLVERS=${DNS_RESOLVERS}
EOF
fi
set -o nounset   # abort on unbound variable

# Make sure that only the root user can access the environment variables file
chown root:root /etc/nginx/environment
chmod og-rwx /etc/nginx/environment

cat > /usr/local/bin/template_nginx_config.sh << 'EOF'
#!/usr/bin/env bash

ME=$(basename $0)

auto_envsubst() {
  local template_dir="${NGINX_ENVSUBST_TEMPLATE_DIR:-/etc/nginx/templates}"
  local suffix="${NGINX_ENVSUBST_TEMPLATE_SUFFIX:-.template}"
  local output_dir="${NGINX_ENVSUBST_OUTPUT_DIR:-/etc/nginx/conf.d}"

  local template defined_envs relative_path output_path subdir
  defined_envs=$(printf '${%s} ' $(env | cut -d= -f1))
  [ -d "$template_dir" ] || return 0
  if [ ! -w "$output_dir" ]; then
    echo "$ME: ERROR: $template_dir exists, but $output_dir is not writable"
    return 0
  fi
  find "$template_dir" -follow -type f -name "*$suffix" -print | while read -r template; do
    relative_path="${template#$template_dir/}"
    output_path="$output_dir/${relative_path%$suffix}"
    subdir=$(dirname "$relative_path")
    # create a subdirectory where the template file exists
    mkdir -p "$output_dir/$subdir"
    echo "$ME: Running envsubst on $template to $output_path"
    envsubst "$defined_envs" < "$template" > "$output_path"
  done
}

# Attempt to read DNS Resolvers from /etc/resolv.conf
if [ -z ${DNS_RESOLVERS+x} ]; then
  export DNS_RESOLVERS="$(cat /etc/resolv.conf | grep nameserver | cut -d' ' -f2 | xargs)"
fi

auto_envsubst
EOF
chmod +x /usr/local/bin/template_nginx_config.sh

echo "▶ Reconfiguring systemd for S3 Gateway"
mkdir -p /etc/systemd/system/nginx.service.d
cat > /etc/systemd/system/nginx.service.d/override.conf << 'EOF'
[Service]
EnvironmentFile=/etc/nginx/environment
ExecStartPre=/usr/local/bin/template_nginx_config.sh
EOF
systemctl daemon-reload

echo "▶ Creating NGINX configuration for S3 Gateway"
mkdir -p /etc/nginx/include
mkdir -p /etc/nginx/conf.d/gateway
mkdir -p /etc/nginx/templates/gateway

function download() {
  wget --quiet --output-document="$2" "https://raw.githubusercontent.com/nginx-serverless/nginx-s3-gateway-v2/master/$1"
}

if [ ! -f /etc/nginx/nginx.conf.orig ]; then
  mv /etc/nginx/nginx.conf /etc/nginx/nginx.conf.orig
fi

if [ ! -f /etc/nginx/conf.d/default.conf.orig ]; then
  mv /etc/nginx/conf.d/default.conf /etc/nginx/conf.d/default.conf.orig
fi

cat > /etc/nginx/nginx.conf << 'EOF'
user  nginx;
worker_processes  auto;

error_log  /var/log/nginx/error.log notice;
pid        /var/run/nginx.pid;

# NJS module used for implementing S3 authentication
load_module modules/ngx_http_js_module.so;
load_module modules/ngx_http_xslt_filter_module.so;

# Preserve S3 environment variables for worker threads
EOF

# Only include these env vars if we are not using a instance profile credential
# to obtain S3 permissions.
if [ $uses_iam_creds -eq 0 ]; then
  cat >> "/etc/nginx/environment" << EOF
env AWS_ACCESS_KEY_ID;
env AWS_SECRET_ACCESS_KEY;
EOF
fi

cat >> /etc/nginx/nginx.conf << 'EOF'
env S3_BUCKET_NAME;
env S3_SERVER;
env S3_SERVER_PORT;
env S3_SERVER_PROTO;
env S3_REGION;
env AWS_SIGS_VERSION;
env AWS_DEBUG;
env S3_STYLE;
env ALLOW_DIRECTORY_LIST;

env LAMBDA_SERVER;
env LAMBDA_REGION;

events {
    worker_connections  1024;
}


http {
    include       /etc/nginx/mime.types;
    default_type  application/octet-stream;

    log_format  main  '$remote_addr - $remote_user [$time_local] "$request" '
                      '$status $body_bytes_sent "$http_referer" '
                      '"$http_user_agent" "$http_x_forwarded_for"';

    access_log  /var/log/nginx/access.log  main;

    sendfile        on;
    #tcp_nopush     on;

    keepalive_timeout  65;

    #gzip  on;

    # Settings for S3 cache
    proxy_cache_path /var/cache/nginx/s3_proxy
    levels=1:2
    keys_zone=s3_cache:10m
    max_size=10g
    inactive=60m
    use_temp_path=off;

    include /etc/nginx/conf.d/*.conf;
}
EOF

download "common/etc/nginx/include/listing.xsl" "/etc/nginx/include/listing.xsl"
download "common/etc/nginx/include/aws_common.js" "/etc/nginx/include/aws_common.js"
download "common/etc/nginx/include/s3gateway.js" "/etc/nginx/include/s3gateway.js"
download "common/etc/nginx/include/lambda_gateway.js" "/etc/nginx/include/lambda_gateway.js"
download "common/etc/nginx/templates/default.conf.template" "/etc/nginx/templates/default.conf.template"
download "common/etc/nginx/templates/gateway/v2_headers.conf.template" "/etc/nginx/templates/gateway/v2_headers.conf.template"
download "common/etc/nginx/templates/gateway/v2_js_vars.conf.template" "/etc/nginx/templates/gateway/v2_js_vars.conf.template"
download "common/etc/nginx/templates/gateway/v4_headers.conf.template" "/etc/nginx/templates/gateway/v4_headers.conf.template"
download "common/etc/nginx/templates/gateway/v4_js_vars.conf.template" "/etc/nginx/templates/gateway/v4_js_vars.conf.template"
download "oss/etc/nginx/templates/upstreams.conf.template" "/etc/nginx/templates/upstreams.conf.template"
download "oss/etc/nginx/conf.d/gateway/server_variables.conf" "/etc/nginx/conf.d/gateway/server_variables.conf"
download "common/etc/nginx/templates/gateway/cors.conf.template" "/etc/nginx/templates/gateway/cors.conf.template"
download "common/etc/nginx/templates/gateway/js_fetch_trusted_certificate.conf.template" "/etc/nginx/templates/gateway/js_fetch_trusted_certificate.conf.template"
download "common/etc/nginx/templates/gateway/s3listing_location.conf.template" "/etc/nginx/templates/gateway/s3listing_location.conf.template"
download "common/etc/nginx/templates/gateway/s3_location.conf.template" "/etc/nginx/templates/gateway/s3_location.conf.template"
download "common/etc/nginx/templates/gateway/s3_server.conf.template" "/etc/nginx/templates/gateway/s3_server.conf.template"

echo "▶ Creating directory for proxy cache"
mkdir -p /var/cache/nginx/s3_proxy
chown nginx:nginx /var/cache/nginx/s3_proxy

echo "▶ Starting NGINX"
systemctl start nginx
