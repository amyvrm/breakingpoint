#!/usr/bin/env groovy

node('aws&&docker')
{
	// SEC
	withCredentials([[$class: 'AmazonWebServicesCredentialsBinding', accessKeyVariable: 'S3_AWS_ACCESS_KEY',
                        credentialsId: 'aws-dslabs-purpleteam-account', secretKeyVariable: 'S3_AWS_SECRET_KEY'],
					 string(credentialsId: 'bluechakra_test_workflow_webhook', variable: 'breakingpoint_teams_webhook')])
    {
        deleteDir()
        def aws_s3_bucket_name = params.AWS_S3_BUCKET_NAME
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
        wrap([$class: 'BuildUser'])
        {
            build_user = "${env.BUILD_USER}"
        }
        infra_image = docker.build("tp-operation", "-f docker_files/DockerfileTpOperation .")
        infra_image.inside
        {
            stage('get tp filter id')
            {
                  // replacing the below python file with latest code
//                sh("python3 src/find_new_filter.py --access_key_id ${S3_AWS_ACCESS_KEY}         \
                sh("python3 src/new_tp_filter.py --access_key_id ${S3_AWS_ACCESS_KEY}         \
                                                   --secret_key ${S3_AWS_SECRET_KEY}            \
                                                   --bucket_name ${aws_s3_bucket_name}          \
                                                   --dv_metadata_path ${dv_metadata_path}       \
                                                   --teams_webhook_url \'${breakingpoint_teams_webhook}\'  \
                                                   --jenkins_url ${env.BUILD_URL}                   \
                                                   --build_user \'${build_user}\'")
            }
        }
        stage('run TP Regression')
        {
            build quietPeriod: 10, job: 'tp-regression'
        }
    }
}
