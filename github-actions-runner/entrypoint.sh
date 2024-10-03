#!/bin/bash
echo "Ent"

if [ -n "${GITHUB_APP_ID}" ] && [ -n "${GITHUB_APP_INSTALLATION_ID}" ]; then
  echo "Using GitHub App authentication"

  URI="https://api.github.com"
  API_VERSION=v3
  API_HEADER="Accept: application/vnd.github.${API_VERSION}+json"
  CONTENT_LENGTH_HEADER="Content-Length: 0"
  APP_INSTALLATIONS_URI="${URI}/app/installations"

  JWT_IAT_DRIFT=60
  JWT_EXP_DELTA=600
  JWT_JOSE_HEADER='{
      "alg": "RS256",
      "typ": "JWT"
  }'

  build_jwt_payload() {
      now=$(date +%s)
      iat=$((now - JWT_IAT_DRIFT))
      exp=$((iat + JWT_EXP_DELTA))
      payload=$(printf '{"iat":%d,"exp":%d,"iss":"%s"}' "$iat" "$exp" "$GITHUB_APP_ID")
      echo "${payload}" | tr -d '\n'
  }

  base64url() {
      base64 | tr '+/' '-_' | tr -d '=\n'
  }

  rs256_sign() {
      openssl dgst -binary -sha256 -sign <(echo "$1")
  }

  jwt_payload=$(build_jwt_payload)
  echo "JWT payload: ${jwt_payload}"
  encoded_jwt_parts=$(base64url <<<"${JWT_JOSE_HEADER}").$(base64url <<<"${jwt_payload}")
  encoded_mac=$(echo -n "${encoded_jwt_parts}" | rs256_sign "$(cat ./private-key.pem)" | base64url)
  generated_jwt="${encoded_jwt_parts}.${encoded_mac}"

  echo "Github App JWT generated ${generated_jwt}"

  auth_header="Authorization: Bearer ${generated_jwt}"
  access_token_url="${URI}/app/installations/${GITHUB_APP_INSTALLATION_ID}/access_tokens"
  access_token=$(curl -sX POST \
      -H "${CONTENT_LENGTH_HEADER}" \
      -H "${auth_header}" \
      -H "${API_HEADER}" \
      "${access_token_url}" | \
      jq --raw-output .token)

  if [ -z "${access_token}" ]; then
    echo "Failed to acquire Github App access token"
    exit 1
  else
    echo "Github App access token acquired"
    echo "Access token: ${access_token}"

    FULL_URL="${URI}/repos/${GH_URL}/actions/runners/registration-token"
    echo "Registering runner for repository: ${GH_URL}"

    REGISTRATION_TOKEN="$(curl -XPOST -fsSL \
      -H "${CONTENT_LENGTH_HEADER}" \
      -H "Authorization: Bearer ${access_token}" \
      -H "${API_HEADER}" \
      "${FULL_URL}" \
      | jq -r '.token')"

    echo "Registration token: ${REGISTRATION_TOKEN}"
    echo "Full URL: ${FULL_URL}"

    if [ -z "${REGISTRATION_TOKEN}" ]; then
      echo "Failed to acquire runner registration token"
      exit 1
    else
      echo "Runner registration token acquired"
    fi
  fi
else
  echo "GitHub App credentials are not set"
  exit 1
fi

./config.sh --url "https://github.com/ARTM-Corpo" --runnergroup Default --token $REGISTRATION_TOKEN --work /home/builder/actions-runner/runner --labels self-hosted,Linux,X64 --unattended && ./run.sh 