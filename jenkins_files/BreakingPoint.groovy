#!/usr/bin/env groovy

node('aws&&docker')
{
	// SEC
	withCredentials([[$class: 'AmazonWebServicesCredentialsBinding', accessKeyVariable: 'AWS_ACCESS_KEY',
                        credentialsId: 'STAGING_AWS', secretKeyVariable: 'AWS_SECRET_KEY'],
                        [$class: 'AmazonWebServicesCredentialsBinding', accessKeyVariable: 'S3_AWS_ACCESS_KEY',
                        credentialsId: 'aws-dslabs-purpleteam-account', secretKeyVariable: 'S3_AWS_SECRET_KEY'],
//                         [$class: 'AmazonWebServicesCredentialsBinding', accessKeyVariable: 'S3_AWS_ACCESS_KEY',
//                            credentialsId: 'aws-kloudkatana-s3', secretKeyVariable: 'S3_AWS_SECRET_KEY'],
//                        credentialsId: 'dslabs-jenkins-automation-credentials', secretKeyVariable: 'S3_AWS_SECRET_KEY'],
                        usernamePassword(credentialsId: 'bps-cred', usernameVariable: 'bps_user',
					                                                    passwordVariable: 'bps_pwd'),
					//  string(credentialsId: 'bluechakra_test_workflow_webhook', variable: 'breakingpoint_teams_webhook'),
					 string(credentialsId: 'bluechakra_test_workflow_webhook', variable: 'blueckara-test-noti'),
                     file(credentialsId: 'pem-file-dslabs_automation', variable: 'PEM_FILE_PATH')])
    {
        deleteDir()
        def bps_system = "10.207.16.230"
//        def bps_search_strikes = "Adobe Acrobat Reader DC resetForm Use After Free"
        def bps_search_strikes = params.SEARCH_STRIKES
        def bps_number_of_filter = params.NUMBER_OF_STRIKES
//        dvlabs-breakingpoint-pcaps
        def aws_s3_bucket_name = params.AWS_S3_BUCKET_NAME
//        infrastructure as code variables
        def iac_path = "iac_src"
        def plan = "create.tfplan"
        def destroy_auto = "destroy.tfplan"
        def terminate = params.TERMINATE_INSTANCE
        def dv_metadata_folder = "dep/metadata"
        def dv_metadata_path = "${dv_metadata_folder}/dvreferences.xml"
        currentBuild.displayName = "#${env.BUILD_NUMBER}"
        def build_user = ""
        stage('Git checkout')
        {
            checkout scm
            dir(dv_metadata_folder)
            {
                git branch: 'master', credentialsId: 'su-dslabs-automation-token',
                    url: 'https://dsgithub.trendmicro.com/TP-DVLabs/DV_metadata.git'
            }
        }
        stage("dump pem file")
        {
            // Dump the secret file content into a new file
            sh "cat ${env.PEM_FILE_PATH} > ${iac_path}/key/dslabs_automation.pem"
        }
        wrap([$class: 'BuildUser'])
        {
            build_user = "${env.BUILD_USER}"
        }
        try
        {
            infra_image = docker.build("bp-image", "-f docker_files/Dockerfile .")
            infra_image.inside
            {
//                stage('Get Pcaps')
//                {
//                    sh("python3 src/bps_run_cves.py --bps_system ${bps_system} --bps_user ${bps_user} --bps_pass ${bps_pwd} --bps_search_strikes \"${bps_search_strikes}\"")
//                }
                stage('Spin EC2 and Run BP test')
                {
                    sh "terraform -chdir=${iac_path} init"
                    sh "terraform -chdir=${iac_path} validate"
                    sh("terraform -chdir=${iac_path} plan -var=\'access_key=${AWS_ACCESS_KEY}\'              \
                                                           -var=\'secret_key=${AWS_SECRET_KEY}\'             \
                                                           -var=\'workspace=${WORKSPACE}\'                   \
                                                           -var=\'bps_system=${bps_system}\'                 \
                                                           -var=\'bps_user=${bps_user}\'                     \
                                                           -var=\'bps_pass=${bps_pwd}\'                     \
                                                           -var=\'bps_search_strikes=${bps_search_strikes}\' \
                                                           -var=\'bps_number_of_filter=${bps_number_of_filter}\' \
                                                           -var=\'s3_access_key_id=${S3_AWS_ACCESS_KEY}\'        \
                                                           -var=\'s3_secret_key=${S3_AWS_SECRET_KEY}\' \
                                                           -var=\'bucket_name=${aws_s3_bucket_name}\' \
                                                           -var=\'dv_metadata_path=${dv_metadata_path}\'  \
                                                           -var=\'teams_webhook_url=${breakingpoint_teams_webhook}\'  \
                                                           -var=\'jenkins_url=${env.BUILD_URL}\'                      \
                                                           -var=\'build_user=${build_user}\'                     \
                                                           -out ${plan}")
                    sh "terraform -chdir=${iac_path} apply -auto-approve ${plan}"
                }
                currentBuild.result = 'SUCCESS'
                stage('Find New Filter')
                {
                    build quietPeriod: 10, job: 'find-new-filters'
                }
            }
        }
        catch (e)
        {
            error "catch ${e}"
        }
        finally
        {
            infra_image.inside
            {
                if ("${terminate}" == 'true')
                {
                    stage('Terminate Infra')
                    {
                        echo "Terminating the instance"
                        sh("terraform -chdir=${iac_path} plan -var=\'access_key=${AWS_ACCESS_KEY}\'               \
                                                               -var=\'secret_key=${AWS_SECRET_KEY}\'              \
                                                               -var=\'workspace=${WORKSPACE}\'                    \
                                                               -var=\'bps_system=${bps_system}\'                  \
                                                               -var=\'bps_user=${bps_user}\'                      \
                                                               -var=\'bps_pass=${bps_pwd}\'                       \
                                                               -var=\'bps_search_strikes=${bps_search_strikes}\'  \
                                                               -var=\'bps_number_of_filter=${bps_number_of_filter}\' \
                                                               -var=\'s3_access_key_id=${S3_AWS_ACCESS_KEY}\'     \
                                                               -var=\'s3_secret_key=${S3_AWS_SECRET_KEY}\'        \
                                                               -var=\'bucket_name=${aws_s3_bucket_name}\'         \
                                                               -var=\'dv_metadata_path=${dv_metadata_path}\'     \
                                                               -var=\'teams_webhook_url=${breakingpoint_teams_webhook}\'  \
                                                               -var=\'jenkins_url=${env.BUILD_URL}\'                   \
                                                               -var=\'build_user=${build_user}\'                     \
                                                               -destroy -out ${destroy_auto}")
                        sh "terraform -chdir=${iac_path} apply ${destroy_auto}"
                        echo "Terminated the EC2 instance"
                    }
                }
                else
                {
                    stage('Keep Infra')
                    {
                        echo "Keeping the instance in AWS"
                        dir(iac_path)
                        {
                            sh "terraform output amazon2_user"
                            sh "terraform output amazon2_ip"
                        }
                    }
                }
            }
        }
    }
}
