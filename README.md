Azure Workload Identity
=======================

Demo script for AWI public preview.

Refer to official docs: https://azure.github.io/azure-workload-identity

```sh
RG_NAME=aks-demos
CLUSTER_NAME=aks-demos
LOCATION=australiasoutheast

# Register the feature flag for access to the public preview feature
az feature register --name EnableOIDCIssuerPreview --namespace Microsoft.ContainerService
az feature list -o table --query "[?contains(name, 'Microsoft.ContainerService/EnableOIDCIssuerPreview')].{Name:name,State:properties.state}"
az provider register --namespace Microsoft.ContainerService

az extension update --name aks-preview

# Create an AKS cluster with OIDC issuer enabled
az group create -n $RG_NAME -l $LOCATION
az aks create --resource-group $RG_NAME --name $CLUSTER_NAME --enable-oidc-issuer --generate-ssh-keys
az aks get-credentials --resource-group $RG_NAME --name $CLUSTER_NAME --overwrite-existing

# Output the OIDC issuer URL
OIDC_ISSUER_URL=$(az aks show --resource-group $RG_NAME --name $CLUSTER_NAME --query "oidcIssuerProfile.issuerUrl" -otsv)
echo $OIDC_ISSUER_URL
# ==> https://oidc.prod-aks.azure.com/[GUID]/

AZURE_TENANT_ID="$(az account show --query tenantId -o tsv)"

# Install the required Azure Workload Identity mutating admission webhook controller
helm repo add azure-workload-identity https://azure.github.io/azure-workload-identity/charts
helm repo update
helm install workload-identity-webhook azure-workload-identity/workload-identity-webhook \
   --namespace azure-workload-identity-system \
   --create-namespace \
   --set azureTenantID="${AZURE_TENANT_ID}"

kubectl get pod -n azure-workload-identity-system

# Install the optional AZWI CLI helper tool
wget https://github.com/Azure/azure-workload-identity/releases/download/v0.12.0/azwi-v0.12.0-linux-amd64.tar.gz
tar xzvf azwi-v0.12.0-linux-amd64.tar.gz azwi
chmod +x azwi
sudo mv azwi /usr/local/bin
azwi

# Quickstart (see: https://azure.github.io/azure-workload-identity/docs/quick-start.html)
# environment variables for the Azure Key Vault resource
export KEYVAULT_NAME="azwi-kv-$(openssl rand -hex 2)"
export KEYVAULT_SECRET_NAME="my-secret"
export RESOURCE_GROUP="azwi-quickstart-$(openssl rand -hex 2)"
export LOCATION="australiasoutheast"

# Environment variables for the AAD application
export APPLICATION_NAME="aadwidemo"

# Environment variables for the Kubernetes service account & federated identity credential
export SERVICE_ACCOUNT_NAMESPACE="default"
export SERVICE_ACCOUNT_NAME="workload-identity-sa"
export SERVICE_ACCOUNT_ISSUER=$OIDC_ISSUER_URL

az group create --name "${RESOURCE_GROUP}" --location "${LOCATION}"

az keyvault create --resource-group "${RESOURCE_GROUP}" \
   --location "${LOCATION}" \
   --name "${KEYVAULT_NAME}"

az keyvault secret set --vault-name "${KEYVAULT_NAME}" \
   --name "${KEYVAULT_SECRET_NAME}" \
   --value "Hello\!"

# Create an AAD application and grant permissions to access the secret

# With AZWI:
# azwi serviceaccount create phase app --aad-application-name "${APPLICATION_NAME}"

az ad sp create-for-rbac --name "${APPLICATION_NAME}"

# Set access policy for the AAD application to access the keyvault secret:
export APPLICATION_CLIENT_ID="$(az ad sp list --display-name "${APPLICATION_NAME}" --query '[0].appId' -otsv)"
az keyvault set-policy --name "${KEYVAULT_NAME}" \
  --secret-permissions get \
  --spn "${APPLICATION_CLIENT_ID}"

# Create a Kubernetes service account

# With AZWI:
# azwi serviceaccount create phase sa \
#   --aad-application-name "${APPLICATION_NAME}" \
#   --service-account-namespace "${SERVICE_ACCOUNT_NAMESPACE}" \
#   --service-account-name "${SERVICE_ACCOUNT_NAME}"

cat <<EOF | kubectl apply -f -
apiVersion: v1
kind: ServiceAccount
metadata:
  annotations:
    azure.workload.identity/client-id: ${APPLICATION_CLIENT_ID}
  labels:
    azure.workload.identity/use: "true"
  name: ${SERVICE_ACCOUNT_NAME}
  namespace: ${SERVICE_ACCOUNT_NAMESPACE}
EOF

kubectl get sa ${SERVICE_ACCOUNT_NAME} -o yaml

# Establish federated identity credential for trust between the AAD application and the service account issuer & subject

# With AZWI:
# azwi serviceaccount create phase federated-identity \
#   --aad-application-name "${APPLICATION_NAME}" \
#   --service-account-namespace "${SERVICE_ACCOUNT_NAMESPACE}" \
#   --service-account-name "${SERVICE_ACCOUNT_NAME}" \
#   --service-account-issuer-url "${SERVICE_ACCOUNT_ISSUER}"

# Get the object ID of the AAD application
export APPLICATION_OBJECT_ID="$(az ad app show --id ${APPLICATION_CLIENT_ID} --query id -otsv)"

cat <<EOF > body.json
{
  "name": "kubernetes-federated-credential",
  "issuer": "${SERVICE_ACCOUNT_ISSUER}",
  "subject": "system:serviceaccount:${SERVICE_ACCOUNT_NAMESPACE}:${SERVICE_ACCOUNT_NAME}",
  "description": "Kubernetes service account federated credential",
  "audiences": [
    "api://AzureADTokenExchange"
  ]
}
EOF

az rest --method POST --uri "https://graph.microsoft.com/beta/applications/${APPLICATION_OBJECT_ID}/federatedIdentityCredentials" --body @body.json

# Check the federated credential assigned to the app registration in Azure Portal by searching with its client ID
echo APPLICATION_CLIENT_ID=$APPLICATION_CLIENT_ID

# Deploy workload(s)

# Demo 1 - MSAL with Golang

cat <<EOF | kubectl apply -f -
apiVersion: v1
kind: Pod
metadata:
  name: quick-start
  namespace: ${SERVICE_ACCOUNT_NAMESPACE}
spec:
  serviceAccountName: ${SERVICE_ACCOUNT_NAME}
  containers:
    - image: ghcr.io/azure/azure-workload-identity/msal-go
      name: oidc
      env:
      - name: KEYVAULT_NAME
        value: ${KEYVAULT_NAME}
      - name: SECRET_NAME
        value: ${KEYVAULT_SECRET_NAME}
  nodeSelector:
    kubernetes.io/os: linux
EOF

# To check whether all properties are injected properly by the webhook:
kubectl get pod quick-start
kubectl describe pod quick-start

# To verify that pod is able to get a token and access the secret from the Key Vault:
kubectl logs quick-start

# Demo 2 - Azure CLI

cat <<EOF | kubectl apply -f -
apiVersion: apps/v1
kind: Deployment
metadata:
  name: azcli-deployment
  namespace: ${SERVICE_ACCOUNT_NAMESPACE}
  labels:
    app: azcli
spec:
  replicas: 1
  selector:
    matchLabels:
      app: azcli
  template:
    metadata:
      labels:
        app: azcli
    spec:
      serviceAccountName: ${SERVICE_ACCOUNT_NAME}
      containers:
        - name: azcli
          image: mcr.microsoft.com/azure-cli:latest
          command:
            - "/bin/bash"
            - "-c"
            - "sleep infinity"
          env:
          - name: KEYVAULT_NAME
            value: ${KEYVAULT_NAME}
          - name: SECRET_NAME
            value: ${KEYVAULT_SECRET_NAME}
      nodeSelector:
        kubernetes.io/os: linux
EOF

# For demo purposes, grant read access to the Resource Group containing the Key Vault secret for Azure CLI access
SUBSCRIPTION_ID=$(az account show --query id -o tsv)
az role assignment create --assignee $APPLICATION_CLIENT_ID --role "Reader" --scope /subscriptions/$SUBSCRIPTION_ID/resourceGroups/$RESOURCE_GROUP

kubectl get $(kubectl get pod -l app=azcli -o name)
kubectl describe $(kubectl get pod -l app=azcli -o name)

kubectl exec -ti $(kubectl get pod -l app=azcli -o name) -- /bin/bash
cat $AZURE_FEDERATED_TOKEN_FILE
# ==> eyJ<....snip...>
# Paste the JWT into https://jwt.io to decode it

az login --federated-token "$(cat $AZURE_FEDERATED_TOKEN_FILE)" --debug \
--service-principal -u $AZURE_CLIENT_ID -t $AZURE_TENANT_ID

az keyvault list -o table
az keyvault secret show --vault-name azwi-kv-ba1b --name my-secret
exit
```

Check OpenID Configuration in the AKS cluster:

```sh
curl $OIDC_ISSUER_URL.well-known/openid-configuration
```

Cleanup
-------

```sh
# ----- Minimum cleanup to repeat demo -----

# Demo 1
kubectl delete pod quick-start

# Demo 2
kubectl delete deployment azcli-deployment

# Service account
kubectl delete sa "${SERVICE_ACCOUNT_NAME}" --namespace "${SERVICE_ACCOUNT_NAMESPACE}"

# ----- Full cleanup -----

# Cluster
az group delete --name "${RESOURCE_GROUP}"

# AAD application
az ad sp delete --id "${APPLICATION_CLIENT_ID}"
```

References
----------

* https://azure.github.io/azure-workload-identity/docs/introduction.html
