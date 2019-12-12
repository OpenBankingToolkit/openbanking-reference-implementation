#Variables:
PASSWORD=changeit
DOMAIN=dev-ob.forgerock.financial

FOLDER_CA=ca
FOLDER_JWK_STORE=jwkstore

FOLDER_TPP=tpp

FOLDER_ASPSP=aspsp

FOLDER_JWKMS=jwkms

FOLDER_OB=ob
FOLDER_COMMON=common

FOLDER_SCGW=scgw

FOLDER_ADMIN=admin
FOLDER_DIRECTORY=directory
FOLDER_METRICS=metrics
FOLDER_MONITORING=monitoring

FOLDER_DEV_PORTAL=devportal
FOLDER_DOCS=devportal/docs
FOLDER_REGISTER=devportal/register

#Default key parameters

TRANSPORT_KEY_ALGO=RSA
TRANSPORT_KEY_SIZE=2048
TRANSPORT_KEY_SIGNING_ALGO=SHA256withRSA

SIGNING_KEY_ALGO=RSA
SIGNING_KEY_SIZE=2048
SIGNING_KEY_SIGNING_ALGO=SHA256withRSA

VALIDITY=825
#OB directory
OB_ORGANISATION_ID=OpenBanking
OB_ROOT_CA_PATH=obOfficialCertificates/OB_SandBox_PP_Root_CA.cer
OB_ROOT_CA_ALIAS=obsandboxrootca

ASPSP_ORGANISATION_ID=0015800001041REAAY
ASPSP_SOFTWARE_ID=5Nc0QXeZpQp8OsjiDLwdXZ

RS_OU=$(ASPSP_ORGANISATION_ID)
RS_CN=$(ASPSP_SOFTWARE_ID)
RS_O=$(OB_ORGANISATION_ID)
RS_C=GB

TPP_ORGANISATION_ID=sOcPXVfMgEHGs2wpvA

TPP_SOFTWARE_ID=50jjZli0J1YBD0ElxD9o2G
TPP_OU=$(TPP_ORGANISATION_ID)
TPP_CN=$(TPP_SOFTWARE_ID)
TPP_O=$(OB_ORGANISATION_ID)
TPP_C=GB

OB_OFFICIAL_CERT_TRANSPORT_RS=rs-ob-transport

OB_OFFICIAL_CERT_TRANSPORT_TPP=tpp-ob-transport

#
# CA
#
OBRI_INTERNAL_CA_ALIAS=obri-internal-ca
OBRI_INTERNAL_CA_CRT=$(FOLDER_CA)/obri-internal-ca.crt
OBRI_INTERNAL_CA_P12=$(FOLDER_CA)/obri-internal-ca.p12
OBRI_INTERNAL_CA_KEYSTORE=$(FOLDER_CA)/obri-internal-ca-keystore.jks
OBRI_INTERNAL_CA_DNAME='CN=$(OBRI_INTERNAL_CA_ALIAS),OU=$(FORGEROCK_OU),O=$(FORGEROCK_O),L=$(FORGEROCK_L),ST=$(FORGEROCK_ST),C=$(FORGEROCK_C)'

OBRI_EXTERNAL_CA_ALIAS=obri-external-ca
OBRI_EXTERNAL_CA_CRT=$(FOLDER_CA)/obri-external-ca.crt
OBRI_EXTERNAL_CA_P12=$(FOLDER_CA)/obri-external-ca.p12
OBRI_EXTERNAL_CA_KEYSTORE=$(FOLDER_CA)/obri-external-ca-keystore.jks
OBRI_EXTERNAL_CA_DNAME='CN=$(OBRI_EXTERNAL_CA_ALIAS),OU=$(FORGEROCK_OU),O=$(FORGEROCK_O),L=$(FORGEROCK_L),ST=$(FORGEROCK_ST),C=$(FORGEROCK_C)'

JVM_TRUSTSTORE=${JAVA_HOME}/jre/lib/security/cacerts

#
# micro-services application names
#
#ASPSP
APP_AS_API=as-api
APP_RS_UI=rs-ui
APP_RS_API=rs-api
APP_RS_RCS=rs-rcs
APP_RS_SIMULATOR=rs-simulator
APP_RS_STORE=rs-store

#Directory
APP_DIRECTORY_SERVICES=directory-services
APP_JWKMS=jwkms

#TPP
APP_TPP=tpp-core
APP_SHOP=shop
APP_ACCOUNT=account

#SCGW
APP_SCGW=scgw

#Backstage
APP_SWAGGER_UI=swagger-ui
APP_MONITORING=monitoring
APP_METRICS_SERVICES=metrics-services
APP_ADMIN=admin

#devportal
APP_DOCS=docs
APP_REGISTER=register

#openam
APP_OPENAM=openam

#
# HOSTNAME
#

#ASPSP
HOSTNAME_ASPSP_RS=rs.aspsp.${DOMAIN}
HOSTNAME_ASPSP_RS_MATLS=matls.rs.aspsp.${DOMAIN}
HOSTNAME_ASPSP_RCS=rcs.aspsp.${DOMAIN}
HOSTNAME_ASPSP_UI=bank.${DOMAIN}
HOSTNAME_ASPSP_BANK_SERVICE=service.bank.${DOMAIN}
HOSTNAME_ASPSP_AS=as.aspsp.${DOMAIN}
HOSTNAME_ASPSP_AS_MATLS=matls.as.aspsp.${DOMAIN}
HOSTNAME_ASPSP_AS_TOP_REALM=am.${DOMAIN}
HOSTNAME_ASPSP_AS_TOP_REALM_MATLS=matls.am.${DOMAIN}
HOSTNAME_ASPSP_AS_MATLS=matls.as.aspsp.${DOMAIN}
HOSTNAME_ASPSP_RS_STORE=rs-store.aspsp.${DOMAIN}
HOSTNAME_ASPSP_RS_SIMULATOR=simulator.rs.aspsp.${DOMAIN}
#Directory
HOSTNAME_AUTH_UI=auth.${DOMAIN}
HOSTNAME_DIRECTORY_UI=directory.${DOMAIN}
HOSTNAME_DIRECTORY_SERVICE=service.directory.${DOMAIN}
HOSTNAME_JWKMS=jwkms.${DOMAIN}

#TPP
HOSTNAME_TPP=tpp-core.${DOMAIN}
HOSTNAME_ACCOUNT=account.${DOMAIN}
HOSTNAME_SHOP=shop.${DOMAIN}

#SCGW
HOSTNAME_SCGW=scgw.${DOMAIN}

#backstage
HOSTNAME_SWAGGER=swagger.${DOMAIN}
HOSTNAME_ADMIN=admin.${DOMAIN}
HOSTNAME_METRICS_SERVICE=service.metrics.${DOMAIN}
HOSTNAME_MONITORING=monitoring.${DOMAIN}
HOSTNAME_TPP_UI=tpp.${DOMAIN}
HOSTNAME_TPP_NODE=node.tpp.${DOMAIN}
HOSTNAME_ANALYTICS_UI=analytics.${DOMAIN}
HOSTNAME_ANALYTICS_SERVICE=service.analytics.${DOMAIN}
HOSTNAME_ANALYTICS_NODE=node.analytics.${DOMAIN}
HOSTNAME_ANALYTICS_PDF=pdf.analytics.${DOMAIN}
HOSTNAME_CONFIG=config.${DOMAIN}

#devportal
HOSTNAME_DOCS=docs.${DOMAIN}
HOSTNAME_REGISTER=service.register.${DOMAIN}
HOSTNAME_REGISTER_UI=register.${DOMAIN}

#obie
HOSTNAME_OB_AISP=obaisp.${DOMAIN}

HOSTNAME_COMMON=wildcard.${DOMAIN}
#
# DNAME
#
FORGEROCK_OU=forgerock.financial
FORGEROCK_O=ForgeRock
FORGEROCK_L=Bristol
FORGEROCK_ST=Avon
FORGEROCK_C=UK
# CN = Common Name
# OU = Organization Unit
# O  = Organization Name
# L  = Locality Name
# ST = State Name
# C  = Country (2-letter Country Code)
# E  = Email
# For server certificates, the Common Name (CN) must be the hostname
DNAME_COMMON='CN=$(HOSTNAME_COMMON),OU=$(FORGEROCK_OU),O=$(FORGEROCK_O),L=$(FORGEROCK_L),ST=$(FORGEROCK_ST),C=$(FORGEROCK_C)'

DNAME_ASPSP_RS='CN=$(HOSTNAME_ASPSP_RS),OU=$(FORGEROCK_OU),O=$(FORGEROCK_O),L=$(FORGEROCK_L),ST=$(FORGEROCK_ST),C=$(FORGEROCK_C)'
DNAME_ASPSP_RCS='CN=$(HOSTNAME_ASPSP_RCS),OU=$(FORGEROCK_OU),O=$(FORGEROCK_O),L=$(FORGEROCK_L),ST=$(FORGEROCK_ST),C=$(FORGEROCK_C)'
DNAME_ASPSP_UI='CN=$(HOSTNAME_ASPSP_UI),OU=$(FORGEROCK_OU),O=$(FORGEROCK_O),L=$(FORGEROCK_L),ST=$(FORGEROCK_ST),C=$(FORGEROCK_C)'
DNAME_ASPSP_AS='CN=$(HOSTNAME_ASPSP_AS),OU=$(FORGEROCK_OU),O=$(FORGEROCK_O),L=$(FORGEROCK_L),ST=$(FORGEROCK_ST),C=$(FORGEROCK_C)'

DNAME_REGISTER_UI='CN=$(HOSTNAME_REGISTER_UI),OU=$(FORGEROCK_OU),O=$(FORGEROCK_O),L=$(FORGEROCK_L),ST=$(FORGEROCK_ST),C=$(FORGEROCK_C)'

DNAME_TPP='CN=$(HOSTNAME_TPP),OU=$(FORGEROCK_OU),O=$(FORGEROCK_O),L=$(FORGEROCK_L),ST=$(FORGEROCK_ST),C=$(FORGEROCK_C)'

DNAME_AISP='CN=$(HOSTNAME_ACCOUNT),OU=$(FORGEROCK_OU),O=$(FORGEROCK_O),L=$(FORGEROCK_L),ST=$(FORGEROCK_ST),C=$(FORGEROCK_C)'
DNAME_SHOP='CN=$(HOSTNAME_SHOP),OU=$(FORGEROCK_OU),O=$(FORGEROCK_O),L=$(FORGEROCK_L),ST=$(FORGEROCK_ST),C=$(FORGEROCK_C)'

DNAME_JWKMS='CN=$(HOSTNAME_JWKMS),OU=$(FORGEROCK_OU),O=$(FORGEROCK_O),L=$(FORGEROCK_L),ST=$(FORGEROCK_ST),C=$(FORGEROCK_C)'
DNAME_SCGW='CN=$(HOSTNAME_SCGW),OU=$(FORGEROCK_OU),O=$(FORGEROCK_O),L=$(FORGEROCK_L),ST=$(FORGEROCK_ST),C=$(FORGEROCK_C)'
DNAME_SWAGGER='CN=$(HOSTNAME_SWAGGER),OU=$(FORGEROCK_OU),O=$(FORGEROCK_O),L=$(FORGEROCK_L),ST=$(FORGEROCK_ST),C=$(FORGEROCK_C)'
DNAME_ADMIN='CN=$(HOSTNAME_ADMIN),OU=$(FORGEROCK_OU),O=$(FORGEROCK_O),L=$(FORGEROCK_L),ST=$(FORGEROCK_ST),C=$(FORGEROCK_C)'
DNAME_MONITORING='CN=$(HOSTNAME_MONITORING),OU=$(FORGEROCK_OU),O=$(FORGEROCK_O),L=$(FORGEROCK_L),ST=$(FORGEROCK_ST),C=$(FORGEROCK_C)'
DNAME_ANALYTICS='CN=$(HOSTNAME_ANALYTICS_UI),OU=$(FORGEROCK_OU),O=$(FORGEROCK_O),L=$(FORGEROCK_L),ST=$(FORGEROCK_ST),C=$(FORGEROCK_C)'
DNAME_TPP='CN=$(HOSTNAME_TPP_UI),OU=$(FORGEROCK_OU),O=$(FORGEROCK_O),L=$(FORGEROCK_L),ST=$(FORGEROCK_ST),C=$(FORGEROCK_C)'
DNAME_CONFIG='CN=$(HOSTNAME_CONFIG),OU=$(FORGEROCK_OU),O=$(FORGEROCK_O),L=$(FORGEROCK_L),ST=$(FORGEROCK_ST),C=$(FORGEROCK_C)'

DNAME_DIRECTORY_UI='CN=$(HOSTNAME_DIRECTORY_UI),OU=$(FORGEROCK_OU),O=$(FORGEROCK_O),L=$(FORGEROCK_L),ST=$(FORGEROCK_ST),C=$(FORGEROCK_C)'
DNAME_DIRECTORY_SERVICE='CN=$(HOSTNAME_DIRECTORY_SERVICE),OU=$(FORGEROCK_OU),O=$(FORGEROCK_O),L=$(FORGEROCK_L),ST=$(FORGEROCK_ST),C=$(FORGEROCK_C)'

DNAME_METRICS_SERVICE='CN=$(HOSTNAME_METRICS_SERVICE),OU=$(FORGEROCK_OU),O=$(FORGEROCK_O),L=$(FORGEROCK_L),ST=$(FORGEROCK_ST),C=$(FORGEROCK_C)'

DNAME_DOCS='CN=$(HOSTNAME_DOCS),OU=$(FORGEROCK_OU),O=$(FORGEROCK_O),L=$(FORGEROCK_L),ST=$(FORGEROCK_ST),C=$(FORGEROCK_C)'
DNAME_REGISTER='CN=$(HOSTNAME_REGISTER),OU=$(FORGEROCK_OU),O=$(FORGEROCK_O),L=$(FORGEROCK_L),ST=$(FORGEROCK_ST),C=$(FORGEROCK_C)'

#OB signed certificates
DNAME_OB_AISP='CN=$(HOSTNAME_OB_AISP),OU=$(FORGEROCK_OU),O=$(FORGEROCK_O),L=$(FORGEROCK_L),ST=$(FORGEROCK_ST),C=$(FORGEROCK_C)'
DNAME_RS_OB='CN=$(RS_CN),OU=$(RS_OU),O=$(RS_O),C=$(RS_C)'
DNAME_TPP_OB='CN=$(TPP_CN),OU=$(TPP_OU),O=$(TPP_O),C=$(FORGEROCK_C)'

KEYSTORE_COMMON="${FOLDER_COMMON}/keystore.jks"
KEYSTORE_ASPSP="${FOLDER_ASPSP}/keystore.jks"
KEYSTORE_TPP="${FOLDER_TPP}/keystore.jks"
KEYSTORE_JWKMS="${FOLDER_JWKMS}/keystore.jks"
KEYSTORE_SCGW="${FOLDER_SCGW}/keystore.jks"
KEYSTORE_OB="${FOLDER_OB}/keystore.jks"
KEYSTORE_ADMIN="${FOLDER_ADMIN}/keystore.jks"
KEYSTORE_DIRECTORY="${FOLDER_DIRECTORY}/keystore.jks"
KEYSTORE_METRICS="${FOLDER_METRICS}/keystore.jks"
KEYSTORE_DOCS="${FOLDER_DOCS}/keystore.jks"
KEYSTORE_REGISTER="${FOLDER_REGISTER}/keystore.jks"
KEYSTORE_MONITORING="${FOLDER_MONITORING}/keystore.jks"
#
# Keystore
#
TRUSTSTORE_COMMON="${FOLDER_COMMON}/truststore.jks"

JWKS_STORE="${FOLDER_JWK_STORE}/jwksstore.pfx"

ASPSP_KEYSTORE_FOLDER=../forgerock-openbanking-aspsp/forgerock-openbanking-aspsp-rs/forgerock-openbanking-rs-api/src/main/resources/unfiltered/keystore/
ASPSP_AS_API_KEYSTORE_FOLDER=../forgerock-openbanking-aspsp/forgerock-openbanking-aspsp-as/forgerock-openbanking-as-api/src/main/resources/unfiltered/keystore/
ASPSP_RCS_KEYSTORE_FOLDER=../forgerock-openbanking-aspsp/forgerock-openbanking-aspsp-rs/forgerock-openbanking-rs-rcs/src/main/resources/unfiltered/keystore/
RS_UI_KEYSTORE_FOLDER=../forgerock-openbanking-aspsp/forgerock-openbanking-aspsp-rs/forgerock-openbanking-rs-ui/src/main/resources/unfiltered/keystore/
RS_STORE_KEYSTORE_FOLDER=../forgerock-openbanking-aspsp/forgerock-openbanking-aspsp-rs/forgerock-openbanking-rs-store/src/main/resources/unfiltered/keystore/
RS_SIMULATOR_KEYSTORE_FOLDER=../forgerock-openbanking-aspsp/forgerock-openbanking-aspsp-rs/forgerock-openbanking-rs-simulator/src/main/resources/unfiltered/keystore/

TPP_KEYSTORE_FOLDER=../forgerock-openbanking-tpp/forgerock-openbanking-tpp-core/src/main/resources/unfiltered/keystore/
AISP_KEYSTORE_FOLDER=../forgerock-openbanking-tpp/forgerock-openbanking-account/src/main/resources/unfiltered/keystore/
SHOP_KEYSTORE_FOLDER=../forgerock-openbanking-tpp/forgerock-openbanking-shop/src/main/resources/keystore

AM_KEYSTORE_FOLDER=forgerock@openbanking:~/keystore/

SCGW_KEYSTORE_FOLDER=../forgerock-openbanking-gateway/src/main/resources/unfiltered/keystore/

JWKMS_KEYSTORE_FOLDER=../forgerock-openbanking-jwkms/src/main/resources/unfiltered/keystore/
DIRECTORY_SERVICE_KEYSTORE_FOLDER=../forgerock-openbanking-directory-services/src/main/resources/unfiltered/keystore/
DIRECTORY_UI_KEYSTORE_FOLDER=../forgerock-openbanking-directory/forgerock-openbanking-directory-ui/src/main/resources/unfiltered/keystore/

ADMIN_KEYSTORE_FOLDER=../forgerock-openbanking-backstage/forgerock-openbanking-admin/src/main/resources/unfiltered/keystore/
METRICS_SERVICE_KEYSTORE_FOLDER=../forgerock-openbanking-backstage/forgerock-openbanking-metrics/forgerock-openbanking-metrics-services/src/main/resources/unfiltered/keystore/
SWAGGER_KEYSTORE_FOLDER=../forgerock-openbanking-backstage/forgerock-openbanking-swagger-ui/src/main/resources/unfiltered/keystore/
MONITORING_KEYSTORE_FOLDER=../forgerock-openbanking-backstage/forgerock-openbanking-monitoring/src/main/resources/unfiltered/keystore/

DOCS_KEYSTORE_FOLDER=../forgerock-openbanking-devportal/forgerock-openbanking-docs/src/main/resources/unfiltered/keystore/
REGISTER_KEYSTORE_FOLDER=../forgerock-openbanking-devportal/forgerock-openbanking-register/src/main/resources/unfiltered/keystore/

#Makefile commands:

all:	clean \
 init-folder \
 create-keystores \
 create-truststore \
 create-keys \

common: clean-common \
        init-folder-common \
        create-common-keystore \
        create-common-key

aspsp: clean-aspsp clean-common \
        init-folder-aspsp init-folder-common \
        create-aspsp-keystore create-common-keystore \
        create-truststore \
        create-aspsp-key create-common-key \
        deploy-aspsp

tpp: clean-tpp clean-common \
        init-folder-tpp init-folder-common \
        create-tpp-keystore create-common-keystore \
        create-truststore \
        create-tpp-key create-common-key

scgw: clean-scgw clean-common \
        init-folder-scgw init-folder-common \
        create-scgw-keystore create-common-keystore \
        create-truststore \
        create-scgw-key create-common-key \
        deploy-scgw


admin: clean-admin \
        init-folder-admin \
        create-admin-keystore \
        create-admin-key \
        deploy-admin

directory: clean-directory \
        init-folder-directory \
        create-directory-keystore \
        create-directory-key \
        deploy-directory

metrics: clean-metrics \
        init-folder-metrics \
        create-metrics-keystore \
        create-metrics-key \
        deploy-metrics

devportal: clean-devportal \
        init-folder-devportal \
        create-devportal-keystore \
        create-devportal-key \
        deploy-devportal

swagger: clean-common \
        init-folder-common \
        create-common-keystore \
        create-common-key \
        deploy-swagger

monitoring: clean-monitoring \
        init-folder-monitoring \
        create-monitoring-keystore \
        create-monitoring-key \
        deploy-monitoring

jwkms-store: clean-jwkstore init-folder-jwkstore create-jwkstore deploy-jwkms-store

init-folder: init-folder-aspsp init-folder-common init-folder-jwkms init-folder-ob \
init-folder-scgw init-folder-admin init-folder-directory init-folder-metrics init-folder-devportal init-folder-monitoring

init-folder-ca:
	# Generate ca folder
	mkdir ${FOLDER_CA}

init-folder-jwkstore:
	# Generate JWK store folder
	mkdir ${FOLDER_JWK_STORE}

init-folder-aspsp:
	# Generate aisp folder
	mkdir ${FOLDER_ASPSP}

init-folder-tpp:
	# Generate tpp folder
	mkdir ${FOLDER_TPP}

init-folder-pisp:
	# Generate pisp folder
	mkdir ${FOLDER_PISP}

init-folder-common:
	# Generate common folder
	mkdir ${FOLDER_COMMON}

init-folder-jwkms:
	# Generate jwkms folder
	mkdir ${FOLDER_JWKMS}

init-folder-ob:
	# Generate ob folder
	mkdir ${FOLDER_OB}

init-folder-scgw:
	# Generate SCGW folder
	mkdir ${FOLDER_SCGW}

init-folder-admin:
	# Generate admin folder
	mkdir ${FOLDER_ADMIN}

init-folder-directory:
	# Generate directory folder
	mkdir ${FOLDER_DIRECTORY}

init-folder-metrics:
	# Generate metrics folder
	mkdir ${FOLDER_METRICS}

init-folder-devportal: init-folder-devportal-folder init-folder-docs init-folder-register

init-folder-devportal-folder:
	# Generate devportal folder
	mkdir ${FOLDER_DEV_PORTAL}

init-folder-docs:
	# Generate docs folder
	mkdir ${FOLDER_DOCS}


init-folder-register:
	# Generate register folder
	mkdir ${FOLDER_REGISTER}

init-folder-monitoring:
	# Generate monitoring folder
	mkdir ${FOLDER_MONITORING}
#
# Create CA
#
define create_certificate-authority
	$(eval CA_ALIAS=$(1))
	$(eval CA_CRT=$(2))
	$(eval CA_P12=$(3))
	$(eval CA_KEYSTORE=$(4))
	$(eval CA_DNAME=$(5))

	@echo "Generate $(CA_ALIAS) CA"
	keytool -genkey -alias $(CA_ALIAS) -ext BC=ca:true \
		-keyalg $(TRANSPORT_KEY_ALGO) -keysize $(TRANSPORT_KEY_SIZE) -sigalg $(TRANSPORT_KEY_SIGNING_ALGO) \
		-keypass $(PASSWORD) \
		-validity $(VALIDITY) -dname $(CA_DNAME) \
		-keystore $(CA_KEYSTORE) -storepass $(PASSWORD)

	@echo "Export CA public key"
	keytool -export -alias $(CA_ALIAS) -file $(CA_CRT) -rfc \
		-keystore $(CA_KEYSTORE) -storepass $(PASSWORD)

	@echo "Export CA private key"
	keytool -importkeystore -srcalias $(CA_ALIAS) \
		-srckeystore $(CA_KEYSTORE) -srcstorepass $(PASSWORD) \
		-destkeystore $(CA_P12) -deststorepass $(PASSWORD) \
		-deststoretype PKCS12
endef

create-obri-internal-authority:
	# Create OBRI internal CA
	$(call create_certificate-authority,$(OBRI_INTERNAL_CA_ALIAS), $(OBRI_INTERNAL_CA_CRT), $(OBRI_INTERNAL_CA_P12), \
	$(OBRI_INTERNAL_CA_KEYSTORE), $(OBRI_INTERNAL_CA_DNAME))

create-obri-external-authority:
	# Create OBRI internal CA
	$(call create_certificate-authority,$(OBRI_EXTERNAL_CA_ALIAS), $(OBRI_EXTERNAL_CA_CRT), $(OBRI_EXTERNAL_CA_P12), \
	$(OBRI_EXTERNAL_CA_KEYSTORE), $(OBRI_EXTERNAL_CA_DNAME))

#
# Create keystores
#

create-keystores: create-common-keystore create-aspsp-keystore \
create-jwkms-keystore create-ob-keystore create-scgw-keystore create-admin-keystore create-directory-keystore \
create-metrics-keystore create-devportal-keystore create-monitoring-keystore

create-common-keystore:
	# Import CA into common keystore
	keytool -importkeystore \
	-deststorepass $(PASSWORD) -destkeystore $(KEYSTORE_COMMON) \
	-srckeystore $(OBRI_INTERNAL_CA_P12) -srcstoretype PKCS12 -srcstorepass $(PASSWORD)
	# Import External CA
	keytool -import -trustcacerts -noprompt -alias $(OBRI_EXTERNAL_CA_ALIAS) -file $(OBRI_EXTERNAL_CA_CRT) \
		-keystore $(KEYSTORE_COMMON) -storepass $(PASSWORD)

create-aspsp-keystore:
	# Import CA into aspsp keystore
	keytool -importkeystore \
	-deststorepass $(PASSWORD) -destkeystore $(KEYSTORE_ASPSP) \
	-srckeystore $(OBRI_INTERNAL_CA_P12) -srcstoretype PKCS12 -srcstorepass $(PASSWORD)

	#Import OB CA
	keytool -import -alias $(OB_ROOT_CA_ALIAS) -noprompt -file $(OB_ROOT_CA_PATH) -keystore $(KEYSTORE_ASPSP) -storepass $(PASSWORD)
	# Import External CA
	keytool -import -trustcacerts -noprompt -alias $(OBRI_EXTERNAL_CA_ALIAS) -file $(OBRI_EXTERNAL_CA_CRT) \
		-keystore $(KEYSTORE_ASPSP) -storepass $(PASSWORD)

create-tpp-keystore:
	# Import CA into tpp keystore
	keytool -importkeystore \
	-deststorepass $(PASSWORD) -destkeystore $(KEYSTORE_TPP) \
	-srckeystore $(OBRI_INTERNAL_CA_P12) -srcstoretype PKCS12 -srcstorepass $(PASSWORD)

	#Import OB CA
	keytool -import -alias $(OB_ROOT_CA_ALIAS) -file $(OB_ROOT_CA_PATH) -keystore $(KEYSTORE_TPP)  -noprompt  -storepass $(PASSWORD)
	# Import External CA
	keytool -import -trustcacerts -noprompt -alias $(OBRI_EXTERNAL_CA_ALIAS) -file $(OBRI_EXTERNAL_CA_CRT) \
		-keystore $(KEYSTORE_TPP) -storepass $(PASSWORD)

create-jwkms-keystore:
	# Import CA into jwkms keystore
	keytool -importkeystore \
	-deststorepass $(PASSWORD) -destkeystore $(KEYSTORE_JWKMS) \
	-srckeystore $(OBRI_INTERNAL_CA_P12) -srcstoretype PKCS12 -srcstorepass $(PASSWORD)
	# Import External CA
	keytool -import -trustcacerts -noprompt -alias $(OBRI_EXTERNAL_CA_ALIAS) -file $(OBRI_EXTERNAL_CA_CRT) \
		-keystore $(KEYSTORE_JWKMS) -storepass $(PASSWORD)

create-ob-keystore:
	# Import CA into jwkms keystore
	keytool -importkeystore \
	-deststorepass $(PASSWORD) -destkeystore $(KEYSTORE_OB) \
	-srckeystore $(OBRI_INTERNAL_CA_P12) -srcstoretype PKCS12 -srcstorepass $(PASSWORD)

	#Import OB CA
	keytool -import -alias $(OB_ROOT_CA_ALIAS) -file $(OB_ROOT_CA_PATH) -keystore $(KEYSTORE_OB)  -noprompt  -storepass $(PASSWORD)
	# Import External CA
	keytool -import -trustcacerts -noprompt -alias $(OBRI_EXTERNAL_CA_ALIAS) -file $(OBRI_EXTERNAL_CA_CRT) \
		-keystore $(KEYSTORE_OB) -storepass $(PASSWORD)

create-scgw-keystore:
	# Import CA into SCGW keystore
	keytool -importkeystore \
	-deststorepass $(PASSWORD) -destkeystore $(KEYSTORE_SCGW) \
	-srckeystore $(OBRI_INTERNAL_CA_P12) -srcstoretype PKCS12 -srcstorepass $(PASSWORD)
	# Import External CA
	keytool -import -trustcacerts -noprompt -alias $(OBRI_EXTERNAL_CA_ALIAS) -file $(OBRI_EXTERNAL_CA_CRT) \
		-keystore $(KEYSTORE_SCGW) -storepass $(PASSWORD)

create-admin-keystore:
	# Import CA into admin keystore
	keytool -importkeystore \
	-deststorepass $(PASSWORD) -destkeystore $(KEYSTORE_ADMIN) \
	-srckeystore $(OBRI_INTERNAL_CA_P12) -srcstoretype PKCS12 -srcstorepass $(PASSWORD)
	# Import External CA
	keytool -import -trustcacerts -noprompt -alias $(OBRI_EXTERNAL_CA_ALIAS) -file $(OBRI_EXTERNAL_CA_CRT) \
		-keystore $(KEYSTORE_ADMIN) -storepass $(PASSWORD)

create-directory-keystore:
	# Import CA into directory keystore
	keytool -importkeystore \
	-deststorepass $(PASSWORD) -destkeystore $(KEYSTORE_DIRECTORY) \
	-srckeystore $(OBRI_INTERNAL_CA_P12) -srcstoretype PKCS12 -srcstorepass $(PASSWORD)
	# Import External CA
	keytool -import -trustcacerts -noprompt -alias $(OBRI_EXTERNAL_CA_ALIAS) -file $(OBRI_EXTERNAL_CA_CRT) \
		-keystore $(KEYSTORE_DIRECTORY) -storepass $(PASSWORD)

create-metrics-keystore:
	# Import CA into metric keystore
	keytool -importkeystore \
	-deststorepass $(PASSWORD) -destkeystore $(KEYSTORE_METRICS) \
	-srckeystore $(OBRI_INTERNAL_CA_P12) -srcstoretype PKCS12 -srcstorepass $(PASSWORD)
	# Import External CA
	keytool -import -trustcacerts -noprompt -alias $(OBRI_EXTERNAL_CA_ALIAS) -file $(OBRI_EXTERNAL_CA_CRT) \
		-keystore $(KEYSTORE_METRICS) -storepass $(PASSWORD)

create-devportal-keystore: create-docs-keystore create-register-keystore

create-docs-keystore:
	# Import CA into docs keystore
	keytool -importkeystore \
	-deststorepass $(PASSWORD) -destkeystore $(KEYSTORE_DOCS) \
	-srckeystore $(OBRI_INTERNAL_CA_P12) -srcstoretype PKCS12 -srcstorepass $(PASSWORD)
	# Import External CA
	keytool -import -trustcacerts -noprompt -alias $(OBRI_EXTERNAL_CA_ALIAS) -file $(OBRI_EXTERNAL_CA_CRT) \
		-keystore $(KEYSTORE_DOCS) -storepass $(PASSWORD)

create-register-keystore:
	# Import CA into register keystore
	keytool -importkeystore \
	-deststorepass $(PASSWORD) -destkeystore $(KEYSTORE_REGISTER) \
	-srckeystore $(OBRI_INTERNAL_CA_P12) -srcstoretype PKCS12 -srcstorepass $(PASSWORD)
	# Import External CA
	keytool -import -trustcacerts -noprompt -alias $(OBRI_EXTERNAL_CA_ALIAS) -file $(OBRI_EXTERNAL_CA_CRT) \
		-keystore $(KEYSTORE_REGISTER) -storepass $(PASSWORD)

create-monitoring-keystore:
	# Import CA into monitoring keystore
	keytool -importkeystore \
	-deststorepass $(PASSWORD) -destkeystore $(KEYSTORE_MONITORING) \
	-srckeystore $(OBRI_INTERNAL_CA_P12) -srcstoretype PKCS12 -srcstorepass $(PASSWORD)
	# Import External CA
	keytool -import -trustcacerts -noprompt -alias $(OBRI_EXTERNAL_CA_ALIAS) -file $(OBRI_EXTERNAL_CA_CRT) \
		-keystore $(KEYSTORE_MONITORING) -storepass $(PASSWORD)
#
# Create Truststores
#
create-truststore:
	# Import CA into aspsp truststore
	keytool -import -trustcacerts -noprompt -alias $(OBRI_INTERNAL_CA_ALIAS) -file $(OBRI_INTERNAL_CA_CRT) \
	    -keystore $(TRUSTSTORE_COMMON) -storepass $(PASSWORD)
	# Import External CA
	keytool -import -trustcacerts -noprompt -alias $(OBRI_EXTERNAL_CA_ALIAS) -file $(OBRI_EXTERNAL_CA_CRT) \
		-keystore $(TRUSTSTORE_COMMON) -storepass $(PASSWORD)

#
# Create JWK store
#
create-jwkstore:
	# Create JWK store
	keytool -importkeystore \
	-deststorepass $(PASSWORD) -destkeystore $(JWKS_STORE) -deststoretype PKCS12 \
	-srckeystore $(OBRI_EXTERNAL_CA_P12) -srcstoretype PKCS12 -srcstorepass $(PASSWORD)


define generate_key
	$(eval ALIAS=$(1))
	$(eval DNAME=$(2))
	$(eval SAN=$(3))
	$(eval KEYSTORE=$(4))
	$(eval PASSWORD=$(5))
	$(eval FOLDER=$(6))
	$(eval KEY_ALGO=$(7))
	$(eval KEY_SIZE=$(8))
	$(eval KEY_SIGNING_ALGO=$(9))
	$(eval BROWSER_CERT=b-$(ALIAS).p12)

	@echo "Generate $(ALIAS) certificate"
	keytool -genkey -alias $(subst wildcard,*,$(ALIAS)) \
	    -keyalg $(KEY_ALGO) -keysize $(KEY_SIZE) -sigalg $(KEY_SIGNING_ALGO) -keypass $(PASSWORD) \
	    -validity $(VALIDITY) -dname $(subst wildcard,*,$(DNAME)) \
	    -ext SAN=$(SAN) \
	    -keystore $(KEYSTORE) -storepass $(PASSWORD)

	@echo "Generate $(ALIAS) certificate signing request"
	keytool -certreq -alias $(subst wildcard,*,$(ALIAS)) -ext BC=ca:true \
	    -keyalg $(KEY_ALGO) -keysize $(KEY_SIZE) -sigalg $(KEY_SIGNING_ALGO) \
	    -validity $(VALIDITY) -file "$(FOLDER)/$(ALIAS).csr" \
	    -ext SAN=$(SAN) \
	    -keystore $(KEYSTORE) -storepass $(PASSWORD)

	@echo "Generate $(ALIAS) signed certificate with the CA"
	keytool -gencert -alias $(OBRI_INTERNAL_CA_ALIAS) \
	    -validity $(VALIDITY) -sigalg $(KEY_SIGNING_ALGO) \
	    -infile "$(FOLDER)/$(ALIAS).csr" -outfile "$(FOLDER)/$(ALIAS).crt" -rfc \
	    -ext SAN=$(SAN) \
	    -keystore $(KEYSTORE) -storepass $(PASSWORD)

	@echo "Import $(ALIAS) signed certificate into $(KEYSTORE)"
	keytool -import -trustcacerts -noprompt -alias $(subst wildcard,*,$(ALIAS)) \
	    -file "$(FOLDER)/$(ALIAS).crt" \
	    -ext SAN=$(SAN) \
	    -keystore $(KEYSTORE) -storepass $(PASSWORD)

	@echo "Export $(ALIAS) private certificate for importing into a browser"
	keytool -importkeystore -srcalias $(subst wildcard,*,$(ALIAS)) \
	    -srckeystore $(KEYSTORE) -srcstorepass $(PASSWORD) \
	    -destkeystore "$(FOLDER)/$(BROWSER_CERT)" -deststorepass $(PASSWORD) \
	    -deststoretype PKCS12

	@echo "Export $(ALIAS) certificate into .key"
	echo $(PASSWORD) > /tmp/pwd.txt
	openssl pkcs12 -in $(FOLDER)/$(BROWSER_CERT)  -nodes -nocerts -out $(FOLDER)/k-$(ALIAS).key -passin file:/tmp/pwd.txt
endef

define generate_transport_key
	$(eval ALIAS=$(1))
	$(eval DNAME=$(2))
	$(eval SAN=$(3))
	$(eval KEYSTORE=$(4))
	$(eval PASSWORD=$(5))
	$(eval FOLDER=$(6))
	$(eval BROWSER_CERT=b-$(ALIAS).p12)

	@echo "Generate transport $(ALIAS) certificate"
	keytool -genkey -alias $(subst wildcard,*,$(ALIAS)) \
		-keyalg $(TRANSPORT_KEY_ALGO) -keysize $(TRANSPORT_KEY_SIZE) -sigalg $(TRANSPORT_KEY_SIGNING_ALGO) \
		-keypass $(PASSWORD) \
		-validity $(VALIDITY) -dname $(subst wildcard,*,$(DNAME)) \
		-ext SAN=$(SAN) \
		-keystore $(KEYSTORE) -storepass $(PASSWORD)

	@echo "Generate $(ALIAS) certificate signing request"
	keytool -certreq -alias $(subst wildcard,*,$(ALIAS)) -ext BC=ca:true \
		-keyalg $(TRANSPORT_KEY_ALGO) -keysize $(TRANSPORT_KEY_SIZE) -sigalg $(TRANSPORT_KEY_SIGNING_ALGO) \
		-validity $(VALIDITY) -file "$(FOLDER)/$(ALIAS).csr" \
		-ext SAN=$(SAN) \
		-keystore $(KEYSTORE) -storepass $(PASSWORD)

	@echo "Generate $(ALIAS) signed certificate with the CA"
	keytool -gencert -alias $(OBRI_INTERNAL_CA_ALIAS) \
		-validity $(VALIDITY) -sigalg $(TRANSPORT_KEY_SIGNING_ALGO) \
		-infile "$(FOLDER)/$(ALIAS).csr" -outfile "$(FOLDER)/$(ALIAS).crt" -rfc \
		-ext SAN=$(SAN) \
		-keystore $(KEYSTORE) -storepass $(PASSWORD)

	@echo "Import $(ALIAS) signed certificate into $(KEYSTORE)"
	keytool -import -trustcacerts -noprompt -alias $(subst wildcard,*,$(ALIAS)) \
		-file "$(FOLDER)/$(ALIAS).crt" \
		-ext SAN=$(SAN) \
		-keystore $(KEYSTORE) -storepass $(PASSWORD)

	@echo "Export $(ALIAS) private certificate for importing into a browser"
	keytool -importkeystore -srcalias $(subst wildcard,*,$(ALIAS)) \
		-srckeystore $(KEYSTORE) -srcstorepass $(PASSWORD) \
		-destkeystore "$(FOLDER)/$(BROWSER_CERT)" -deststorepass $(PASSWORD) \
		-deststoretype PKCS12

	@echo "Export $(ALIAS) certificate into .key"
	echo $(PASSWORD) > /tmp/pwd.txt
	openssl pkcs12 -in $(FOLDER)/$(BROWSER_CERT)  -nodes -nocerts -out $(FOLDER)/k-$(ALIAS).key -passin file:/tmp/pwd.txt
endef

define generate_transport_key_signed_with_ob_ca
	$(eval ALIAS=$(1))
	$(eval DNAME=$(2))
	$(eval SAN=$(3))
	$(eval KEYSTORE=$(4))
	$(eval PASSWORD=$(5))
	$(eval FOLDER=$(6))
	$(eval BROWSER_CERT=b-$(ALIAS).p12)

	@echo "Generate signing $(ALIAS) certificate"
	keytool -genkey -alias $(subst wildcard,*,$(ALIAS)) \
		-keyalg $(SIGNING_KEY_ALGO) -keysize $(SIGNING_KEY_SIZE) -sigalg $(SIGNING_KEY_SIGNING_ALGO) \
		-keypass $(PASSWORD) \
		-validity $(VALIDITY) -dname $(subst wildcard,*,$(DNAME)) \
		-ext SAN=$(SAN) \
		-keystore $(KEYSTORE) -storepass $(PASSWORD)
endef

define generate_csr
	$(eval ALIAS=$(1))
	$(eval DNAME=$(2))
	$(eval KEYSTORE=$(3))
	$(eval PASSWORD=$(4))
	$(eval FOLDER=$(5))
	$(eval KEY_SIZE=$(6))
	$(eval KEY_SIGNING_ALGO=$(7))
	$(eval KEY_ALGO=$(8))
	$(eval SAN=$(9))

	@echo "\nGenerate transport $(ALIAS) certificate\n"
	keytool -genkey -alias $(subst wildcard,*,$(ALIAS)) \
		-keyalg $(KEY_ALGO) -keysize $(KEY_SIZE) -sigalg $(KEY_SIGNING_ALGO) \
		-keypass $(PASSWORD) \
    	-ext SAN=$(SAN) \
		-validity $(VALIDITY) -dname $(subst wildcard,*,$(DNAME)) \
		-keystore $(KEYSTORE) -storepass $(PASSWORD)

	@echo "\nGenerate $(ALIAS) certificate signing request\n"
	keytool -certreq -alias $(subst wildcard,*,$(ALIAS)) -ext BC=ca:true \
		-keyalg $(KEY_ALGO) -keysize $(KEY_SIZE) -sigalg $(KEY_SIGNING_ALGO) \
    	-ext SAN=$(SAN) \
		-validity $(VALIDITY) -file "$(FOLDER)/$(ALIAS).csr" \
		-keystore $(KEYSTORE) -storepass $(PASSWORD)
endef


define import_csr
	$(eval ALIAS=$(1))
	$(eval DNAME=$(2))
	$(eval KEYSTORE=$(3))
	$(eval PASSWORD=$(4))
	$(eval FOLDER=$(5))
	$(eval KEY_SIZE=$(6))
	$(eval KEY_SIGNING_ALGO=$(7))
	$(eval KEY_ALGO=$(8))
	$(eval SAN=$(9))

	@echo "\nImport $(ALIAS) signed certificate into $(KEYSTORE)\n"
	keytool -import -trustcacerts -noprompt -alias $(subst wildcard,*,$(ALIAS)) \
		-file "$(FOLDER)/$(ALIAS).pem"  \
    	-ext SAN=$(SAN) \
		-keystore $(KEYSTORE) -storepass $(PASSWORD)

	@echo "\nExport $(ALIAS) private certificate for importing into a browser\n"
	keytool -importkeystore -srcalias $(subst wildcard,*,$(ALIAS)) \
		-srckeystore $(KEYSTORE) -srcstorepass $(PASSWORD) \
		-destkeystore "$(FOLDER)/$(ALIAS).p12" -deststorepass $(PASSWORD) \
    	-ext SAN=$(SAN) \
		-deststoretype PKCS12

	@echo "\nExport $(ALIAS) certificate into .key\n"
	echo $(PASSWORD) > /tmp/pwd.txt
	openssl pkcs12 -in $(FOLDER)/$(ALIAS).p12  -nodes -nocerts -out $(FOLDER)/$(ALIAS).key -passin file:/tmp/pwd.txt
endef


#
#
# Create Keys
#
create-keys: create-common-key create-aspsp-key create-jwkms-key create-OB-key \
create-scgw-key create-admin-key create-directory-key create-metrics-key create-devportal-key create-monitoring-key

create-common-key:
	$(eval SAN=dns:$(HOSTNAME_ASPSP_RS))
	$(eval SAN=$(SAN),dns:$(HOSTNAME_ASPSP_RCS))
	$(eval SAN=$(SAN),dns:$(HOSTNAME_ASPSP_UI))
	$(eval SAN=$(SAN),dns:$(HOSTNAME_ASPSP_BANK_SERVICE))
	$(eval SAN=$(SAN),dns:$(HOSTNAME_ASPSP_AS))
	$(eval SAN=$(SAN),dns:$(HOSTNAME_ASPSP_AS_TOP_REALM))
	$(eval SAN=$(SAN),dns:$(HOSTNAME_ASPSP_AS_TOP_REALM_MATLS))
	$(eval SAN=$(SAN),dns:$(HOSTNAME_ASPSP_AS_MATLS))
	$(eval SAN=$(SAN),dns:$(HOSTNAME_ASPSP_RS_STORE))
	$(eval SAN=$(SAN),dns:$(HOSTNAME_ASPSP_RS_SIMULATOR))
	$(eval SAN=$(SAN),dns:$(HOSTNAME_AUTH_UI))
	$(eval SAN=$(SAN),dns:$(HOSTNAME_DIRECTORY_SERVICE))
	$(eval SAN=$(SAN),dns:$(HOSTNAME_JWKMS))
	$(eval SAN=$(SAN),dns:$(HOSTNAME_TPP))
	$(eval SAN=$(SAN),dns:$(HOSTNAME_ACCOUNT))
	$(eval SAN=$(SAN),dns:$(HOSTNAME_SHOP))
	$(eval SAN=$(SAN),dns:$(HOSTNAME_SCGW))
	$(eval SAN=$(SAN),dns:$(HOSTNAME_SWAGGER))
	$(eval SAN=$(SAN),dns:$(HOSTNAME_ADMIN))
	$(eval SAN=$(SAN),dns:$(HOSTNAME_METRICS_SERVICE))
	$(eval SAN=$(SAN),dns:$(HOSTNAME_MONITORING))
	$(eval SAN=$(SAN),dns:$(HOSTNAME_TPP_UI))
	$(eval SAN=$(SAN),dns:$(HOSTNAME_TPP_NODE))
	$(eval SAN=$(SAN),dns:$(HOSTNAME_ANALYTICS_UI))
	$(eval SAN=$(SAN),dns:$(HOSTNAME_ANALYTICS_SERVICE))
	$(eval SAN=$(SAN),dns:$(HOSTNAME_ANALYTICS_NODE))
	$(eval SAN=$(SAN),dns:$(HOSTNAME_ANALYTICS_PDF))
	$(eval SAN=$(SAN),dns:$(HOSTNAME_CONFIG))
	$(eval SAN=$(SAN),dns:$(HOSTNAME_DOCS))
	$(eval SAN=$(SAN),dns:$(HOSTNAME_REGISTER))
	$(eval SAN=$(SAN),dns:$(HOSTNAME_REGISTER_UI))

	$(eval SAN=$(SAN),dns:$(APP_ACCOUNT))
	$(eval SAN=$(SAN),dns:$(APP_SHOP))
	$(eval SAN=$(SAN),dns:$(APP_DOCS))
	$(eval SAN=$(SAN),dns:$(APP_RS_UI))
	$(eval SAN=$(SAN),dns:$(APP_SWAGGER_UI))
	$(eval SAN=$(SAN),dns:$(APP_RS_STORE))
	$(eval SAN=$(SAN),dns:$(APP_RS_SIMULATOR))
	$(eval SAN=$(SAN),dns:$(APP_RS_API))
	$(eval SAN=$(SAN),dns:$(APP_AS_API))

	$(call generate_transport_key,$(HOSTNAME_COMMON),$(DNAME_COMMON),\
	$(SAN),\
	$(KEYSTORE_COMMON),$(PASSWORD),$(FOLDER_COMMON))

create-aspsp-key:
	$(eval SAN=dns:$(HOSTNAME_ASPSP_RS))
	$(eval SAN=$(SAN),dns:$(HOSTNAME_ASPSP_AS_TOP_REALM))
	$(eval SAN=$(SAN),dns:$(HOSTNAME_ASPSP_AS_TOP_REALM_MATLS))
	$(eval SAN=$(SAN),dns:$(HOSTNAME_ASPSP_AS))
	$(eval SAN=$(SAN),dns:$(HOSTNAME_ASPSP_RCS))
	$(eval SAN=$(SAN),dns:$(APP_RS_RCS))
	$(eval SAN=$(SAN),dns:$(APP_RS_API))
	$(eval SAN=$(SAN),dns:$(APP_AS_API))
	$(eval SAN=$(SAN),dns:$(APP_OPENAM))


	$(call generate_transport_key,$(HOSTNAME_ASPSP_RS),$(DNAME_ASPSP_RS),\
	$(SAN),\
	$(KEYSTORE_ASPSP),$(PASSWORD),$(FOLDER_ASPSP))

	$(call generate_transport_key,$(HOSTNAME_ASPSP_RCS),$(DNAME_ASPSP_RCS),\
	$(SAN),\
	$(KEYSTORE_ASPSP),$(PASSWORD),$(FOLDER_ASPSP))

	$(call generate_transport_key,$(HOSTNAME_ASPSP_AS),$(DNAME_ASPSP_AS),\
	$(SAN),\
	$(KEYSTORE_ASPSP),$(PASSWORD),$(FOLDER_ASPSP))

create-tpp-key:
	$(eval SAN=dns:$(HOSTNAME_TPP))
	$(eval SAN=$(SAN),dns:$(APP_TPP))

	$(call generate_transport_key,$(HOSTNAME_TPP),$(DNAME_TPP),\
	$(SAN),\
	$(KEYSTORE_TPP),$(PASSWORD),$(FOLDER_TPP))

create-jwkms-key:
	$(eval SAN=dns:$(HOSTNAME_JWKMS))
	$(eval SAN=$(SAN),dns:$(APP_JWKMS))

	$(call generate_transport_key,$(HOSTNAME_JWKMS),$(DNAME_JWKMS),\
	$(SAN),\
	$(KEYSTORE_JWKMS),$(PASSWORD),$(FOLDER_JWKMS))

create-OB-key:
	$(eval SAN=dns:$(HOSTNAME_OB_AISP))

	$(call generate_transport_key,$(HOSTNAME_OB_AISP),$(DNAME_OB_AISP),\
	$(SAN),\
	$(KEYSTORE_OB),$(PASSWORD),$(FOLDER_OB))

create-scgw-key:
	$(eval SAN=dns:$(HOSTNAME_SCGW))
	$(eval SAN=$(SAN),dns:$(HOSTNAME_ACCOUNT),dns:$(HOSTNAME_TPP))
	$(eval SAN=$(SAN),dns:$(HOSTNAME_SHOP))
	$(eval SAN=$(SAN),dns:$(HOSTNAME_ASPSP_RCS))
	$(eval SAN=$(SAN),dns:$(HOSTNAME_ASPSP_RS))
	$(eval SAN=$(SAN),dns:$(HOSTNAME_JWKMS))
	$(eval SAN=$(SAN),dns:$(HOSTNAME_ASPSP_UI))
	$(eval SAN=$(SAN),dns:$(HOSTNAME_DIRECTORY_SERVICE))
	$(eval SAN=$(SAN),dns:$(HOSTNAME_METRICS_SERVICE))
	$(eval SAN=$(SAN),dns:$(HOSTNAME_ASPSP_AS_MATLS))
	$(eval SAN=$(SAN),dns:$(HOSTNAME_ASPSP_AS))
	$(eval SAN=$(SAN),dns:$(HOSTNAME_DOCS))
	$(eval SAN=$(SAN),dns:$(HOSTNAME_ASPSP_BANK_SERVICE))
	$(eval SAN=$(SAN),dns:$(HOSTNAME_REGISTER))
	$(eval SAN=$(SAN),dns:$(HOSTNAME_ASPSP_AS_TOP_REALM))
	$(eval SAN=$(SAN),dns:$(HOSTNAME_ASPSP_AS_TOP_REALM_MATLS))
	$(eval SAN=$(SAN),dns:$(HOSTNAME_CONFIG))

	$(eval SAN=$(SAN),dns:$(APP_SCGW))

	$(call generate_transport_key,$(HOSTNAME_SCGW),$(DNAME_SCGW),\
	$(SAN),\
	$(KEYSTORE_SCGW),$(PASSWORD),$(FOLDER_SCGW))

create-admin-key:
	$(eval SAN=dns:$(HOSTNAME_ADMIN),dns:$(APP_ADMIN))
	$(eval SAN=$(SAN),dns:$(APP_ADMIN))

	$(call generate_transport_key,$(HOSTNAME_ADMIN),$(DNAME_ADMIN),\
	$(SAN),\
	$(KEYSTORE_ADMIN),$(PASSWORD),$(FOLDER_ADMIN))

create-directory-key:
	$(eval SAN=dns:$(HOSTNAME_DIRECTORY_UI))

	$(call generate_transport_key,$(HOSTNAME_DIRECTORY_UI),$(DNAME_DIRECTORY_UI),\
	$(SAN),\
	$(KEYSTORE_DIRECTORY),$(PASSWORD),$(FOLDER_DIRECTORY))

	$(eval SAN=dns:$(HOSTNAME_DIRECTORY_SERVICE))
	$(eval SAN=$(SAN),dns:$(APP_DIRECTORY_SERVICES))

	$(call generate_transport_key,$(HOSTNAME_DIRECTORY_SERVICE),$(DNAME_DIRECTORY_SERVICE),\
	$(SAN),\
	$(KEYSTORE_DIRECTORY),$(PASSWORD),$(FOLDER_DIRECTORY))

create-metrics-key:
	$(eval SAN=dns:$(HOSTNAME_METRICS_SERVICE))
	$(eval SAN=$(SAN),dns:$(APP_METRICS_SERVICES))

	$(call generate_transport_key,$(HOSTNAME_METRICS_SERVICE),$(DNAME_METRICS_SERVICE),\
	$(SAN),\
	$(KEYSTORE_METRICS),$(PASSWORD),$(FOLDER_METRICS))

create-devportal-key: create-docs-key create-register-key
create-docs-key:
	$(eval SAN=dns:$(HOSTNAME_DOCS))
	$(eval SAN=$(SAN),dns:$(APP_DOCS))

	$(call generate_transport_key,$(HOSTNAME_DOCS),$(DNAME_DOCS),\
	$(SAN),\
	$(KEYSTORE_DOCS),$(PASSWORD),$(FOLDER_DOCS))

create-register-key:
	$(eval SAN=dns:$(HOSTNAME_REGISTER))
	$(eval SAN=$(SAN),dns:$(APP_REGISTER))

	$(call generate_transport_key,$(HOSTNAME_REGISTER),$(DNAME_REGISTER),\
	$(SAN),\
	$(KEYSTORE_REGISTER),$(PASSWORD),$(FOLDER_REGISTER))

create-monitoring-key:
	$(eval SAN=dns:$(HOSTNAME_MONITORING))
	$(eval SAN=$(SAN),dns:$(APP_MONITORING))

	$(call generate_transport_key,$(HOSTNAME_MONITORING),$(DNAME_MONITORING),\
	$(SAN),\
	$(KEYSTORE_MONITORING),$(PASSWORD),$(FOLDER_MONITORING))

create-aspsp-csr:
	$(eval SAN=dns:$(HOSTNAME_SCGW))
	$(eval SAN=$(SAN),dns:$(HOSTNAME_ASPSP_RS_MATLS))
	$(eval SAN=$(SAN),dns:$(HOSTNAME_ASPSP_AS_MATLS))

	@echo "\nGenerate a transport CSR\n"
	$(eval ALIAS=transport-$(ASPSP_ORGANISATION_ID))

	$(call generate_csr,$(ALIAS),$(DNAME_RS_OB),\
	$(KEYSTORE_SCGW),$(PASSWORD),$(FOLDER_ASPSP), \
	$(TRANSPORT_KEY_SIZE), $(TRANSPORT_KEY_SIGNING_ALGO), $(TRANSPORT_KEY_ALGO), $(SAN))

import-aspsp-csr:
	@echo "\nimport the transport pem\n"
	$(eval ALIAS=transport-$(ASPSP_ORGANISATION_ID))

	$(call import_csr,$(ALIAS),$(DNAME_RS_OB),\
	$(KEYSTORE_SCGW),$(PASSWORD),$(FOLDER_ASPSP), \
	$(TRANSPORT_KEY_SIZE), $(TRANSPORT_KEY_SIGNING_ALGO), $(TRANSPORT_KEY_ALGO), $(SAN))


create-tpp-request-to-ob:
	$(eval SAN=dns:$(HOSTNAME_TPP))

	$(call generate_transport_key,$(TPP_SOFTWARE_ID),$(DNAME_TPP_OB),\
	$(SAN),\
	$(KEYSTORE_TPP),$(PASSWORD),$(FOLDER_TPP))

	keytool -certreq -alias $(TPP_SOFTWARE_ID)  \
    	    -keyalg $(TRANSPORT_KEY_ALGO) -keysize $(TRANSPORT_KEY_SIZE) -sigalg $(TRANSPORT_KEY_SIGNING_ALGO) \
    	    -dname $(DNAME_TPP_OB) \
    	    -validity $(VALIDITY) -file "$(FOLDER_TPP)/$(TPP_SOFTWARE_ID).csr" \
    	    -ext SAN=$(SAN) \
    	    -keystore $(KEYSTORE_TPP) -storepass $(PASSWORD)

import-tpp-request-to-ob:
	keytool -import -trustcacerts -noprompt -alias $(TPP_SOFTWARE_ID) \
	-file $(FOLDER_TPP)/$(TPP_SOFTWARE_ID).pem \
		-keystore $(KEYSTORE_TPP) -storepass $(PASSWORD)

	@echo "Export $(TPP_SOFTWARE_ID) private certificate for importing into a browser"
	keytool -importkeystore -srcalias $(TPP_SOFTWARE_ID) \
		-srckeystore $(KEYSTORE_TPP) -srcstorepass $(PASSWORD) \
		-destkeystore "$(FOLDER_TPP)/$(TPP_SOFTWARE_ID).p12" -deststorepass $(PASSWORD) \
		-deststoretype PKCS12

	@echo "Export $(TPP_SOFTWARE_ID) certificate into .key"
	echo $(PASSWORD) > /tmp/pwd.txt
	openssl pkcs12 -in "$(FOLDER_TPP)/$(TPP_SOFTWARE_ID).p12"  -nodes -nocerts -out $(FOLDER_TPP)/$(TPP_SOFTWARE_ID).key -passin file:/tmp/pwd.txt


#
# Deploy keystores
#
deploy: deploy-aspsp deploy-scgw\
deploy-jwkms deploy-scgw deploy-admin deploy-directory deploy-metrics deploy-devportal deploy-monitoring

deploy-aspsp: deploy-aspsp-as-api deploy-aspsp-rs-api deploy-aspsp-rcs deploy-aspsp-rs-store deploy-aspsp-rs-simulator deploy-aspsp-rs-ui

deploy-aspsp-as-api:
	# copy ASPSP keystore
	cp $(KEYSTORE_ASPSP) ${ASPSP_AS_API_KEYSTORE_FOLDER}

deploy-aspsp-rs-api:
	# copy ASPSP keystore
	cp $(KEYSTORE_ASPSP) ${ASPSP_KEYSTORE_FOLDER}

deploy-aspsp-rcs:
	# copy ASPSP RCS keystore
	cp $(KEYSTORE_ASPSP) ${ASPSP_RCS_KEYSTORE_FOLDER}

deploy-aspsp-rs-store:
	# copy COMMON keystore to rs store
	cp $(KEYSTORE_COMMON) ${RS_STORE_KEYSTORE_FOLDER}

deploy-aspsp-rs-simulator:
	# copy COMMON keystore to rs simulator
	cp $(KEYSTORE_COMMON) ${RS_SIMULATOR_KEYSTORE_FOLDER}

deploy-aspsp-rs-ui:
	# copy COMMON keystore to rs ui
	cp $(KEYSTORE_COMMON) ${RS_UI_KEYSTORE_FOLDER}

deploy-admin:
	# copy ADMIN keystore
	cp $(KEYSTORE_ADMIN) ${ADMIN_KEYSTORE_FOLDER}

deploy-directory:
	# copy directory keystore
	cp $(KEYSTORE_DIRECTORY) ${DIRECTORY_SERVICE_KEYSTORE_FOLDER}

deploy-metrics:
	# copy metrics keystore
	cp $(KEYSTORE_METRICS) ${METRICS_SERVICE_KEYSTORE_FOLDER}

deploy-devportal: deploy-docs deploy-register
deploy-docs:
	# copy docs keystore
	cp $(KEYSTORE_DOCS) ${DOCS_KEYSTORE_FOLDER}

deploy-register:
	# copy register keystore
	cp $(KEYSTORE_REGISTER) ${REGISTER_KEYSTORE_FOLDER}

deploy-monitoring:
	# copy monitoring keystore
	cp $(KEYSTORE_MONITORING) ${MONITORING_KEYSTORE_FOLDER}

deploy-jwkms:
	# copy JWKMS keystore to jwkms store
	cp $(KEYSTORE_JWKMS) ${JWKMS_KEYSTORE_FOLDER}


deploy-scgw:
	# copy SCGW keystore to SCGW keystore folder
	cp $(KEYSTORE_SCGW) ${SCGW_KEYSTORE_FOLDER}

deploy-jwkms-store:
	# copy jwkms store
	cp $(JWKS_STORE) ${JWKMS_KEYSTORE_FOLDER}

#
# Add CA to JVM truststore
#
add-jvm-truststore:
	# Import CA into jvm truststore
	keytool -import -trustcacerts -noprompt -alias $(OBRI_EXTERNAL_CA_ALIAS) -file $(OBRI_EXTERNAL_CA_CRT) \
	    -keystore $(JVM_TRUSTSTORE) -storepass $(PASSWORD)
	keytool -import -trustcacerts -noprompt -alias $(OBRI_INTERNAL_CA_ALIAS) -file $(OBRI_INTERNAL_CA_CRT) \
	    -keystore $(JVM_TRUSTSTORE) -storepass $(PASSWORD)

#
# Clean
#
clean: clean-aspsp clean-common clean-jwkms clean-ob clean-scgw clean-admin clean-metrics \
clean-directory clean-devportal clean-monitoring

clean-ca:
	# Remove ca
	rm -rf ${FOLDER_CA}
clean-jwkstore:
    # Remove jwk store
	rm -rf ${FOLDER_JWK_STORE}
clean-tpp:
	# Remove tpp
	rm -rf ${FOLDER_TPP}
clean-aspsp:
	# Remove aspsp
	rm -rf ${FOLDER_ASPSP}
clean-common:
	# Remove common
	rm -rf ${FOLDER_COMMON}
clean-jwkms:
	# Remove jwkms
	rm -rf ${FOLDER_JWKMS}
clean-ob:
	# Remove jwkms
	rm -rf ${FOLDER_OB}
clean-scgw:
	# Remove SCGW
	rm -rf ${FOLDER_SCGW}
clean-admin:
	# Remove admin
	rm -rf ${FOLDER_ADMIN}
clean-directory:
	# Remove directory
	rm -rf ${FOLDER_DIRECTORY}
clean-metrics:
	# Remove metrics
	rm -rf ${FOLDER_METRICS}

clean-devportal:
	# Remove dev portal
	rm -rf ${FOLDER_DEV_PORTAL}

clean-monitoring:
	# Remove monitoring
	rm -rf ${FOLDER_MONITORING}

clean-ca-from-jvm-truststore:
	# Remove internal CA
	keytool -delete -noprompt -alias $(OBRI_INTERNAL_CA_ALIAS) -file $(OBRI_INTERNAL_CA_CRT) \
	 -keystore $(JVM_TRUSTSTORE) -storepass $(PASSWORD)
	# Remove internal CA
	keytool -delete -noprompt -alias $(OBRI_EXTERNAL_CA_ALIAS) -file $(OBRI_EXTERNAL_CA_CRT) \
	 -keystore $(JVM_TRUSTSTORE) -storepass $(PASSWORD)
