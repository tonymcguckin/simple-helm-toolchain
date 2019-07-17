#!/bin/bash

## ----------------------------------------------------------------------------
#
# Key Protect API:
#
###
#
# kp instance management:
#
#   create_vault_instance                   :: $KP_SERVICE_NAME $REGION
#   retrieve_vault_instance                 :: $KP_SERVICE_NAME $KP_GUID $REGION
#   update_vault_instance                   :: $KP_SERVICE_NAME $KP_GUID $REGION
#   delete_vault_instance                   :: $KP_SERVICE_NAME $KP_GUID $REGION
#
###
#
# iam cross authenticate an integrated service with keyprotect:
#
#   assign_iam_writer_access_for_service    :: $KP_SERVICE_NAME $KP_GUID $SERVICE_ID
#
###
#
# key management:
#
#   get_root_key                            :: $KP_SERVICE_NAME $KP_GUID $REGION $KP_ACCESS_TOKEN $MY_KEY_MATERIAL
#   get_standard_key                        :: $KP_SERVICE_NAME $KP_GUID $REGION $KP_ACCESS_TOKEN $KP_GUID $MY_KEY_MATERIAL
#   delete_key                              :: $KP_SERVICE_NAME $KP_GUID $REGION
#
## ----------------------------------------------------------------------------

#source <(curl -sSL "https://raw.githubusercontent.com/tonymcguckin/simple-helm-toolchain/master/scripts/key_protect.sh")
#section "Pipeline YML calling Key Protect integration..."
#echo "VAULT_SERVICE_NAME=${VAULT_SERVICE_NAME}"
#echo "VAULT_REGION=${VAULT_REGION}"
#ibmcloud target -g devex-playground
#create_vault_instance "${VAULT_SERVICE_NAME}" "${VAULT_REGION}"
#create_vault_instance "tmgkp1" "ibm:yp:us-south"
#create_vault_instance "tmgkp1" "us-south"
#section "Begin: create_vault_instance: tmgkp1"
#
#if check_exists "$(ibmcloud resource service-instance tmgkp1 2>&1)"; then
#    echo "Key Protect service named 'tmgkp1' already exists"
#else
#    ibmcloud resource service-instance-create tmgkp1 kms tiered-pricing us-south || exit 1
#fi
#
#KP_INSTANCE_ID=$(get_instance_id tmgkp1)
#KP_GUID=$(get_guid tmgkp1)
#echo "KP_INSTANCE_ID=$KP_INSTANCE_ID"
#echo "KP_GUID=$KP_GUID"
#check_value "$KP_INSTANCE_ID"
#check_value "$KP_GUID"
#
#if check_exists "$(ibmcloud resource service-key tmgkp1-acckey-$KP_GUID 2>&1)"; then
#    echo "Key Protect key already exists"
#else
#    ibmcloud resource service-key-create tmgkp1-acckey-$KP_GUID Manager \
#        --instance-id "$KP_INSTANCE_ID" || exit 1
#fi
#
#KP_CREDENTIALS=$(ibmcloud resource service-key tmgkp1-acckey-$KP_GUID --output JSON)
#KP_IAM_APIKEY=$(echo "$KP_CREDENTIALS" | jq -r .[0].credentials.apikey)
#KP_ACCESS_TOKEN=$(get_access_token $KP_IAM_APIKEY)
#KP_MANAGEMENT_URL="https://us-south.kms.cloud.ibm.com/api/v2/keys"
#KP_KEYS=$(curl -s $KP_MANAGEMENT_URL \
#  --header "Authorization: Bearer $KP_ACCESS_TOKEN" \
#  --header "Bluemix-Instance: $KP_GUID")
#check_value "$KP_KEYS"
#
#echo "$KP_KEYS"
#
#if echo $KP_KEYS | jq -e -r '.resources[] | select(.name=="docker_trust_private_key")' > /dev/null; then
#  echo "Docker Trust private key already exists"
#else
#  KP_KEYS=$(curl -s -X POST $KP_MANAGEMENT_URL \
#    --header "Authorization: Bearer $KP_ACCESS_TOKEN" \
#    --header "Bluemix-Instance: $KP_GUID" \
#    --header "Content-Type: application/vnd.ibm.kms.key+json" -d @scripts/docker_trust_private_key.json)
#fi
#
#DT_PRIVATE_KEY_ID=$(echo $KP_KEYS | jq -e -r '.resources[] | select(.name=="docker_trust_private_key") | .id')
#echo "DT_PRIVATE_KEY_ID=$DT_PRIVATE_KEY_ID"
#
#DT_PRIVATE_KEY_VALUE=$(curl -s "${KP_MANAGEMENT_URL}/${DT_PRIVATE_KEY_ID}" \
#    --header "Authorization: Bearer $KP_ACCESS_TOKEN" \
#    --header "Bluemix-Instance: $KP_GUID" \
#    --header "Accept: application/vnd.ibm.kms.key+json")
#
#echo "$DT_PRIVATE_KEY_VALUE"
#
#section "End: create_vault_instance: tmgkp1"

## ----------------------------------------------------------------------------

# get an instance of the secrets vault...
function get_vault_instance {
    ##
    # keyprotect assumed default at the moment but
    # optional hashicorp vault provider should be
    # handled/tested here too...
    
    section "create_vault_instance: $1"
    
    #
    # create_vault_instance service-name region
    #
    # eg: create_vault_instance secure-file-storage-kms region
    ##
    if check_exists "$(ibmcloud resource service-instance $1 2>&1)"; then
        echo "Key Protect service named '$1' already exists"
    else
        ibmcloud resource service-instance-create $1 kms tiered-pricing $2 || exit 1
    fi

    KP_INSTANCE_ID=$(get_instance_id $1)
    KP_GUID=$(get_guid $1)
    echo "KP_INSTANCE_ID=$KP_INSTANCE_ID"
    echo "KP_GUID=$KP_GUID"
    check_value "$KP_INSTANCE_ID"
    check_value "$KP_GUID"

    if check_exists "$(ibmcloud resource service-key $1-acckey-$KP_GUID 2>&1)"; then
        echo "Key Protect key already exists"
    else
        ibmcloud resource service-key-create $1-acckey-$KP_GUID Manager \
            --instance-id "$KP_INSTANCE_ID" || exit 1
    fi
}

## ----------------------------------------------------------------------------

function save_key {
    ##
    # save_key $KP_SERVICE_NAME $KEY_NAME $KEY_MATERIAL
    #

    #source <(curl -sSL "https://raw.githubusercontent.com/tonymcguckin/simple-helm-toolchain/master/scripts/key_protect.sh")

    VAULT_SERVICE_NAME=${VAULT_SERVICE_NAME}
    VAULT_REGION=${VAULT_REGION}
    RESOURCE_GROUP=${RESOURCE_GROUP}
    echo "VAULT_SERVICE_NAME=${VAULT_SERVICE_NAME}"
    echo "VAULT_REGION=${VAULT_REGION}"
    echo "RESOURCE_GROUP=${RESOURCE_GROUP}"

    #ibmcloud target -g $RESOURCE_GROUP
    ibmcloud target -g devex-playground

    KP_SERVICE_NAME="tmgkp1"
    KEY_NAME="0bc3889c3e4b8ca6c61a3f05289c591b55238fda1954f05c1de829309007ff96"
    KEY_MATERIAL="LS0tLS1CRUdJTiBFTkNSWVBURUQgUFJJVkFURSBLRVktLS0tLQpyb2xlOiByb290CgpNSUh1TUVrR0NTcUdTSWIzRFFFRkRUQThNQnNHQ1NxR1NJYjNEUUVGRERBT0JBZ3hvNUVjNHJYWjBnSUNDQUF3CkhRWUpZSVpJQVdVREJBRXFCQkNZVGdGeTJUQkQzbzhLQVlXVmtOZkJCSUdnL1ZFUVpKMzBid0xBNUpnT2l1VWUKZEFqdERKakZuTzZCa1c2alVqUWRyYUF1aDY5VW9RQXFyYTU1M1hhTTQ0d1A1OTZJVDRFR2ZwN1BiNUZDeEdpeApCRVZONHRwdDFMbFM5aVBTMmpVa0xLby84Q2w4UURqcjRqU0dhYWhWMDMzcWwxcE96YkdtU0ZJVFVJMWVrRkNqCkczemcrUFdrVEsrOTlSNGQwdjBZbk8veGJzYzV2Yk42RUhQelJOcGVUOHJJM3hEZmFWckhQV1lLaUZJZ0JiZXMKN3c9PQotLS0tLUVORCBFTkNSWVBURUQgUFJJVkFURSBLRVktLS0tLQo="

    section "Begin: save_key: $KP_SERVICE_NAME"

    REGION=$IBM_CLOUD_REGION
    KP_MANAGEMENT_URL=https://$REGION.kms.cloud.ibm.com/api/v2/keys
    KP_INSTANCE_ID=$(get_instance_id $KP_SERVICE_NAME)
    KP_GUID=$(get_guid $KP_SERVICE_NAME)
    KP_SERVICE_KEY_NAME=$KP_SERVICE_NAME-service-key-$KP_GUID

    check_value $REGION
    check_value $KP_MANAGEMENT_URL
    check_value $KP_INSTANCE_ID
    check_value $KP_GUID
    check_value $KP_SERVICE_KEY_NAME

    ##
    # create an instance of keyprotect if it's not already there...
    ##
    if check_exists "$(ibmcloud resource service-instance $KP_SERVICE_NAME 2>&1)"; then
        echo "Reusing Key Protect service named '$KP_SERVICE_NAME' as it already exists..."
    else
        echo "Creating new Key Protect service instance named '$KP_SERVICE_KEY_NAME'..."
        ibmcloud resource service-instance-create $KP_SERVICE_NAME kms tiered-pricing $REGION || exit 1
    fi

    ##
    # get or generate a service-key for keyprotect...
    # need this in order to work with iam to get credentials...
    ##
    if check_exists "$(ibmcloud resource service-key $KP_SERVICE_KEY_NAME 2>&1)"; then
        echo "Reusing Key Protect service-key '$KP_SERVICE_KEY_NAME' as it already exists..."
    else
        echo "Creating new Key Protect service-key '$KP_SERVICE_KEY_NAME'..."
        ibmcloud resource service-key-create $KP_SERVICE_KEY_NAME Manager \
            --instance-id "$KP_INSTANCE_ID" || exit 1
    fi

    KP_CREDENTIALS=$(ibmcloud resource service-key $KP_SERVICE_KEY_NAME --output JSON)
    check_value $KP_CREDENTIALS
    KP_IAM_APIKEY=$(echo "$KP_CREDENTIALS" | jq -r .[0].credentials.apikey)
    check_value $KP_IAM_APIKEY
    KP_ACCESS_TOKEN=$(get_access_token $KP_IAM_APIKEY)
    check_value $KP_ACCESS_TOKEN

    echo "KP_SERVICE_NAME=$KP_SERVICE_NAME"
    echo "REGION=$REGION"
    echo "KP_MANAGEMENT_URL=$KP_MANAGEMENT_URL"
    echo "KP_INSTANCE_ID=$KP_INSTANCE_ID"
    echo "KP_GUID=$KP_GUID"
    echo "KP_SERVICE_KEY_NAME=$KP_SERVICE_KEY_NAME"
    echo "KP_CREDENTIALS=$KP_CREDENTIALS"
    echo "KP_IAM_APIKEY=$KP_IAM_APIKEY"
    echo "KP_ACCESS_TOKEN=$KP_ACCESS_TOKEN"
    echo "KEY_NAME=$KEY_NAME"
    echo "KEY_MATERIAL=$KEY_MATERIAL"

    # get a list of keys on this kp instance first...
    KP_KEYS=$(curl -s $KP_MANAGEMENT_URL \
    --header "Authorization: Bearer $KP_ACCESS_TOKEN" \
    --header "Bluemix-Instance: $KP_GUID")
    check_value $KP_KEYS

    echo "-----------------"
    echo "Key List (Before):"
    echo "KP_KEYS=$KP_KEYS"
    echo "-----------------"

    # now check if the we're trying to save a key that already preexists...
    if echo $KP_KEYS | jq -e -r '.resources[] | select(.name=="${KEY_NAME}")' > /dev/null; then
        echo "Reusing saved key '${KEY_NAME}' as it already exists..."
    else
        DATA='{
            "metadata": {
                "collectionType": "application/vnd.ibm.kms.key+json",
                "collectionTotal": 1
            },
            "resources": [
              {
                "name": "${KEY_NAME}",
                "type": "application/vnd.ibm.kms.key+json",
                "payload": "$KEY_MATERIAL",
                "extractable": true
              }
            ]
          }'

        echo "DATA=$DATA"

        KP_KEYS=$(curl -s -X POST $KP_MANAGEMENT_URL \
          --header "Authorization: Bearer $KP_ACCESS_TOKEN" \
          --header "Bluemix-Instance: $KP_GUID" \
          --header "Prefer: return=representation" \
          --header "Content-Type: application/vnd.ibm.kms.key+json" \
          -d '{
            "metadata": {
                "collectionType": "application/vnd.ibm.kms.key+json",
                "collectionTotal": 1
            },
            "resources": [
              {
                "name": "0bc3889c3e4b8ca6c61a3f05289c591b55238fda1954f05c1de829309007ff96",
                "type": "application/vnd.ibm.kms.key+json",
                "payload": "LS0tLS1CRUdJTiBFTkNSWVBURUQgUFJJVkFURSBLRVktLS0tLQpyb2xlOiByb290CgpNSUh1TUVrR0NTcUdTSWIzRFFFRkRUQThNQnNHQ1NxR1NJYjNEUUVGRERBT0JBZ3hvNUVjNHJYWjBnSUNDQUF3CkhRWUpZSVpJQVdVREJBRXFCQkNZVGdGeTJUQkQzbzhLQVlXVmtOZkJCSUdnL1ZFUVpKMzBid0xBNUpnT2l1VWUKZEFqdERKakZuTzZCa1c2alVqUWRyYUF1aDY5VW9RQXFyYTU1M1hhTTQ0d1A1OTZJVDRFR2ZwN1BiNUZDeEdpeApCRVZONHRwdDFMbFM5aVBTMmpVa0xLby84Q2w4UURqcjRqU0dhYWhWMDMzcWwxcE96YkdtU0ZJVFVJMWVrRkNqCkczemcrUFdrVEsrOTlSNGQwdjBZbk8veGJzYzV2Yk42RUhQelJOcGVUOHJJM3hEZmFWckhQV1lLaUZJZ0JiZXMKN3c9PQotLS0tLUVORCBFTkNSWVBURUQgUFJJVkFURSBLRVktLS0tLQo=",
                "extractable": true
              }
            ]
          }')

        echo "-----------------"
        echo "Key List (After):"
        echo "KP_KEYS=$KP_KEYS"
        echo "-----------------"
    fi

    # extract the id of our saved key...
    KEY_ID=$(echo $KP_KEYS | jq -e -r '.resources[] | select(.name=="${KEY_NAME}") | .id')
    echo "KEY_ID=$KEY_ID"

    section "End: save_key: $KP_SERVICE_NAME"

    # return the new key id...
    echo $KEY_ID
}

## ----------------------------------------------------------------------------

function assign_iam_writer_access_for_service {
    ##
    # assign_iam_writer_access_for_service $KP_SERVICE_NAME $KP_GUID $SERVICE_ID
    #
    
    section "assign_iam_writer_access_for_service: $1"
    
    EXISTING_POLICIES=$(ibmcloud iam service-policies $SERVICE_ID --output json)
    echo "EXISTING_POLICIES=$EXISTING_POLICIES"
    check_value "$EXISTING_POLICIES"

    # Create a policy to make serviceID a writer for Key Protect
    if echo "$EXISTING_POLICIES" | \
    jq -e -r 'select(.[].resources[].attributes[].name=="serviceInstance" and .[].resources[].attributes[].value=="'$KP_GUID'" and .[].roles[].display_name=="Writer")' > /dev/null; then
        echo "Writer policy on Key Protect already exist for the Service ID"
    else
        ibmcloud iam service-policy-create $SERVICE_ID --roles Writer --service-name kms --service-instance $KP_GUID --force
    fi

    KP_CREDENTIALS=$(ibmcloud resource service-key $1-acckey-$KP_GUID --output JSON)
    KP_IAM_APIKEY=$(echo "$KP_CREDENTIALS" | jq -r .[0].credentials.apikey)
    KP_ACCESS_TOKEN=$(get_access_token $KP_IAM_APIKEY)
}

## ----------------------------------------------------------------------------

function update_vault_instance {
    ##
    # 
    ##
    
    section "update_vault_instance: $KP_SERVICE_NAME"
}

## ----------------------------------------------------------------------------

function delete_vault_instance {
    ##
    # 
    ##
    
    section "delete_vault_instance: $KP_SERVICE_NAME"
}

## ----------------------------------------------------------------------------

function delete_key {
    ##
    # delete_key $KEY_ID
    ##
    
    section "delete_key: $1"


}

## ----------------------------------------------------------------------------

# returns an IAM access token given an API key
function get_access_token {
  IAM_ACCESS_TOKEN_FULL=$(curl -s -k -X POST \
  --header "Content-Type: application/x-www-form-urlencoded" \
  --header "Accept: application/json" \
  --data-urlencode "grant_type=urn:ibm:params:oauth:grant-type:apikey" \
  --data-urlencode "apikey=$1" \
  "https://iam.cloud.ibm.com/identity/token")
  IAM_ACCESS_TOKEN=$(echo "$IAM_ACCESS_TOKEN_FULL" | \
    grep -Eo '"access_token":"[^"]+"' | \
    awk '{split($0,a,":"); print a[2]}' | \
    tr -d \")
  echo $IAM_ACCESS_TOKEN
}

## ----------------------------------------------------------------------------

# returns a service CRN given a service name
function get_instance_id {
  OUTPUT=$(ibmcloud resource service-instance --output JSON $1)
  if (echo $OUTPUT | grep -q "crn:v1" >/dev/null); then
    echo $OUTPUT | jq -r .[0].id
  else
    echo "Failed to get instance ID: $OUTPUT"
    exit 2
  fi
}

## ----------------------------------------------------------------------------

# returns a service GUID given a service name
function get_guid {
  OUTPUT=$(ibmcloud resource service-instance --id $1)
  if (echo $OUTPUT | grep -q "crn:v1" >/dev/null); then
    echo $OUTPUT | awk -F ":" '{print $8}'
  else
    echo "Failed to get GUID: $OUTPUT"
    exit 2
  fi
}

## ----------------------------------------------------------------------------

# outputs a separator banner
function section {
  echo
  echo "####################################################################"
  echo "#"
  echo "# $1"
  echo "#"
  echo "####################################################################"
  echo
}

## ----------------------------------------------------------------------------

function check_exists {
  if echo "$1" | grep -q "not found"; then
    return 1
  fi
  if echo "$1" | grep -q "crn:v1"; then
    return 0
  fi
  echo "Failed to check if object exists: $1"
  exit 2
}

## ----------------------------------------------------------------------------

function check_value {
  if [ -z "$1" ]; then
    exit 1
  fi

  if echo $1 | grep -q -i "failed"; then
    exit 2
  fi
}

## ----------------------------------------------------------------------------
