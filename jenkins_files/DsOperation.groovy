#!/usr/bin/env groovy

node('aws&&docker')
{
    def aws_credential_id = ""
    def aws_region_reg = ""
    def c1ws_url = ""
    def c1ws_credential_id = ""
    def v1_url = ""
    def v1_credential_id = ""

    if("${params.AWS_ACCOUNT}" == "dslabs-purpleteam(891458116976)")
    {
        aws_credential_id = "aws-dslabs-purpleteam-account"
        aws_region_reg = params.AWS_REGION
    }
    if("${params.CLOUDONE_ACCOUNT}" == "staging")
    {
        c1ws_url = "https://staging.deepsecurity.trendmicro.com:443"
        c1ws_credential_id = "staging-c1ws-api"
    }
    if("${params.VISIONONE_ACCOUNT}" == "staging")
    {
        v1_url = "https://api-xdr.visionone.trendmicro.com"
        v1_credential_id = "v1_api_token"
    }
	// SEC
	withCredentials([[$class: 'AmazonWebServicesCredentialsBinding', accessKeyVariable: 'AWS_ACCESS_KEY',
                         credentialsId: 'STAGING_AWS', secretKeyVariable: 'AWS_SECRET_KEY'],
                     [$class: 'AmazonWebServicesCredentialsBinding', accessKeyVariable: 'AWS_ACCESS_KEY_ECR',
					   credentialsId: 'redteam-aws-cred', secretKeyVariable: 'AWS_SECRET_KEY_ECR'],
					  [$class: 'AmazonWebServicesCredentialsBinding', accessKeyVariable: 'AWS_ACCESS_KEY_REG',
					   credentialsId: aws_credential_id, secretKeyVariable: 'AWS_SECRET_KEY_REG'],
					 string(credentialsId: c1ws_credential_id, variable: 'C1WS_API'),
					 string(credentialsId: v1_credential_id, variable: 'V1_API'),
					 string(credentialsId: 'dsdeploy-artifactory-token', variable: 'JFROG_TOKEN'),
					 string(credentialsId: 'teams_bluechakra_v1_regression', variable: 'teams_webhook')])
    {
        deleteDir()
        def v1_repo = "v1-regression"
        def iac_path = "${v1_repo}/iac_run_push"
        def rule_model_repo = "SAE-ThreatExpert-Rule-Model"
        def filter_repo = "SAE-ThreatExpert-Filters"
        def art_repo = "art_lib"
        def ecr_account_id = params.AWS_ACCOUNT_ID
        def ecr_region = params.ECR_REGION
        def ecr_repo = params.ECR_REPOSITORIES
        def image_tag = params.IMAGE_TAGS
        def random_num = "${env.BUILD_NUMBER}"
        def plan = "create.tfplan"
        def destroy_auto = "destroy.tfplan"
        def ctrail_model_list = "all"
        def c1ws_model_list = "all"
        def amazon_ip = ""
        def jfrog_base = "https://jfrog.trendmicro.com/artifactory/dslabs-visionone-generic-test-local"
        def jfrog_url = "${jfrog_base}/${env.JOB_BASE_NAME}/${env.BUILD_NUMBER}"
        def build_user = ""

        currentBuild.displayName = "#${env.BUILD_NUMBER}"
        stage('Git checkout')
        {
            checkout scm
            dir(art_repo)
            {
                git branch: 'main', credentialsId: 'su-dslabs-automation-token',
                    url: 'https://dsgithub.trendmicro.com/dslabs/sae-atomic-script-filters.git'
            }
            dir(rule_model_repo)
            {
                git branch: 'master', credentialsId: 'coretech-ssh-private-key',
                    url: 'git@adc.github.trendmicro.com:XDR-SAE/SAE-ThreatExpert-Rule-Model.git'
//                    url: 'git@github.trendmicro.com:xdr-sae/SAE-ThreatExpert-Rule-Model.git'
            }
            dir(filter_repo)
            {
                git branch: 'master', credentialsId: 'coretech-ssh-private-key',
                url: 'git@adc.github.trendmicro.com:XDR-SAE/SAE-ThreatExpert-Filters.git'
//                url: 'git@github.trendmicro.com:xdr-sae/SAE-ThreatExpert-Filters.git'
            }
        }
        wrap([$class: 'BuildUser'])
        {
            build_user = "${env.BUILD_USER}"
        }

        try
        {
            infra_image = docker.build("v1-regression", "-f docker_files/BuildPushImage .")
            infra_image.inside
            {
                  stage('Automation machine')
                {
                    sh "terraform -chdir=${iac_path} init"
                    sh "terraform -chdir=${iac_path} validate"
                    sh("terraform -chdir=${iac_path} plan -var=\'access_key=${AWS_ACCESS_KEY}\'         \
                                                          -var=\'secret_key=${AWS_SECRET_KEY}\'         \
                                                          -var=\'v1_repo=${v1_repo}\'                   \
                                                           -var=\'art_repo=${art_repo}\'                \
                                                          -var=\'rule_model_repo=${rule_model_repo}\'   \
                                                          -var=\'filter_repo=${filter_repo}\'           \
                                                          -var=\'access_key_ecr=${AWS_ACCESS_KEY_ECR}\' \
                                                          -var=\'secret_key_ecr=${AWS_SECRET_KEY_ECR}\' \
                                                          -var=\'ecr_account_id=${ecr_account_id}\'     \
                                                          -var=\'ecr_region=${ecr_region}\'             \
                                                          -var=\'ecr_repo=${ecr_repo}\'                 \
                                                          -var=\'image_tag=${image_tag}\'               \
                                                          -var=\'access_key_reg=${AWS_ACCESS_KEY_REG}\' \
                                                          -var=\'secret_key_reg=${AWS_SECRET_KEY_REG}\' \
                                                          -var=\'aws_region_reg=${aws_region_reg}\'     \
                                                          -var=\'c1ws_url=${c1ws_url}\'                 \
                                                          -var=\'c1ws_api_key=${C1WS_API}\'             \
                                                          -var=\'v1_url=${v1_url}\'                     \
                                                          -var=\'v1_api_key=${V1_API}\'                 \
                                                          -var=\'ctrail_model_list=${ctrail_model_list}\' \
                                                          -var=\'c1ws_model_list=${c1ws_model_list}\'   \
                                                          -var=\'random_num=${random_num}\'             \
                                                          -var=\'workspace=${WORKSPACE}\'               \
                                                          -var=\'jfrog_url=${jfrog_url}\'               \
                                                          -var=\'jfrog_token=${JFROG_TOKEN}\'           \
                                                          -var=\'webhook=${teams_webhook}\'             \
                                                          -var=\'jenkins_build=${env.BUILD_URL}\'       \
                                                          -var=\'build_user=${build_user}\'             \
                                                          -out ${plan}")
                    try
                    {
                        sh "terraform -chdir=${iac_path} apply -auto-approve ${plan}"
                    }
                    catch(e)
                    {
                        error "catch ${e}"
                    }
                    finally
                    {
//                        dir("${iac_path}")
//                        {
//                           amazon_ip = sh(script: 'terraform output amazon_ip', returnStdout: true).trim()
//                        }
                        stage("Archive artefacts")
                        {
                            sh "mkdir artefacts"
                            sh "wget --header='Authorization: Bearer $JFROG_TOKEN' -P ./artefacts ${jfrog_url}/report.html --no-check-certificate -v "
                            sh "wget --header='Authorization: Bearer $JFROG_TOKEN' -P ./artefacts ${jfrog_url}/report.txt --no-check-certificate -v "
//                            sh("scp -i ${iac_path}/dslabs_automation.pem -o 'StrictHostKeyChecking no' -r ec2-user@${amazon_ip}:/tmp/artefacts/* artefacts/.")
                            archiveArtifacts allowEmptyArchive: true, artifacts: "artefacts/*,artefacts/**/*"
                        }
                    }
                    currentBuild.result = 'SUCCESS'
               }
            }
        }
        catch (e)
        {
            error "catch ${e}"
        }
        finally
        {
            if ("${params.DEBUG}" == "true")
            {
                echo "preserved the infra"
            }
            else
            {
                infra_image = docker.build("v1-regression", "-f ${v1_repo}/docker_files/BuildPushImage .")
                infra_image.inside
                {
                    sh("terraform -chdir=${iac_path} plan -var=\'access_key=${AWS_ACCESS_KEY}\'         \
                                                          -var=\'secret_key=${AWS_SECRET_KEY}\'         \
                                                          -var=\'v1_repo=${v1_repo}\'                   \
                                                          -var=\'art_repo=${art_repo}\'                 \
                                                          -var=\'rule_model_repo=${rule_model_repo}\'   \
                                                          -var=\'filter_repo=${filter_repo}\'           \
                                                          -var=\'access_key_ecr=${AWS_ACCESS_KEY_ECR}\' \
                                                          -var=\'secret_key_ecr=${AWS_SECRET_KEY_ECR}\' \
                                                          -var=\'ecr_account_id=${ecr_account_id}\' \
                                                          -var=\'ecr_region=${ecr_region}\' \
                                                          -var=\'ecr_repo=${ecr_repo}\' \
                                                          -var=\'image_tag=${image_tag}\' \
                                                          -var=\'access_key_reg=${AWS_ACCESS_KEY_REG}\' \
                                                          -var=\'secret_key_reg=${AWS_SECRET_KEY_REG}\' \
                                                          -var=\'aws_region_reg=${aws_region_reg}\' \
                                                          -var=\'c1ws_url=${c1ws_url}\' \
                                                          -var=\'c1ws_api_key=${C1WS_API}\' \
                                                          -var=\'v1_url=${v1_url}\' \
                                                          -var=\'v1_api_key=${V1_API}\' \
                                                          -var=\'ctrail_model_list=${ctrail_model_list}\' \
                                                          -var=\'c1ws_model_list=${c1ws_model_list}\' \
                                                          -var=\'random_num=${random_num}\' \
                                                          -var=\'workspace=${WORKSPACE}\' \
                                                          -var=\'jfrog_url=${jfrog_url}\' \
                                                          -var=\'jfrog_token=${JFROG_TOKEN}\' \
                                                          -var=\'webhook=${teams_webhook}\' \
                                                          -var=\'jenkins_build=${env.BUILD_URL}\' \
                                                          -var=\'build_user=${build_user}\' \
                                                          -destroy -out ${destroy_auto}")
                    sh "terraform -chdir=${iac_path} apply ${destroy_auto}"
                    echo "Terminated the EC2 instance"
               }
            }
        }
    }
}
