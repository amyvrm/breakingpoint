#!/usr/bin/env groovy

node('aws&&docker')
{
	// SEC
	withCredentials([[$class: 'AmazonWebServicesCredentialsBinding', accessKeyVariable: 'S3_AWS_ACCESS_KEY',
                        credentialsId: 'aws-dslabs-purpleteam-account', secretKeyVariable: 'S3_AWS_SECRET_KEY'],
                        usernamePassword(credentialsId: 'tp-attacker-cred', usernameVariable: 'ssh_user',
                                                                            passwordVariable: 'ssh_pwd'),
					 string(credentialsId: 'purple_team_workflow_webhook', variable: 'teams_webhook')])
    {
        deleteDir()
//        def mapping_file = params.DV_FILTERS_LIST_FILE
        def s3_bucket_uri = "s3://dvlabs-breakingpoint-pcaps-test"
        def script_name = "parse_replay_pcap.sh"
        def python_script = "update_tracker_file.py"
        def remote_script_path = "/home/testuser/Desktop/scripts"
        def pcap_path = "${remote_script_path}/pcaps"
        def teams_webhook = "https://trendmicro.webhook.office.com/webhookb2/d6c82240-57b1-41b5-84e8-09def3921052@3e04753a-ae5b-42d4-a86d-d6f05460f9e4/JenkinsCI/b131747740c34e90b770e2a911dea18f/5110c51b-5ae9-4caa-a0a8-aafc778ce125"
        currentBuild.displayName = "#${env.BUILD_NUMBER}"
        def build_user = ""
        stage('Git checkout')
        {
            checkout scm
        }
//        try
//        {
        wrap([$class: 'BuildUser'])
        {
            build_user = "${env.BUILD_USER}"
        }
        def infra_image = docker.build("tp-operation", "-f docker_files/DockerfileTpRunScript .")
        infra_image.inside
        {
            stage('Script to replay pcap')
            {
                test_folder = "/home/testuser/Desktop/test_script"
                pcap_folder = "${test_folder}/pcaps"
                def cmd_output = sh(script: """
                        sshpass -p "${ssh_pwd}" ssh -o StrictHostKeyChecking=no "${ssh_user}"@10.203.202.64 <<EOF
//                            cd "${remote_script_path}"
//                            aws s3 cp "${s3_bucket_uri}/scripts/${script_name}" "${script_name}"
//                            aws s3 cp "${s3_bucket_uri}/scripts/${python_script}" "${python_script}"
//                            bash "${script_name}" "${pcap_path}" SuperUser "${ssh_pwd}"
                            cd "${test_folder}"
                            aws s3 cp "${s3_bucket_uri}/scripts/${script_name}" "${script_name}"
                            aws s3 cp "${s3_bucket_uri}/scripts/${python_script}" "${python_script}"
                            bash "${script_name}" "${pcap_folder}" SuperUser "${ssh_pwd}"
    EOF
                        """, returnStdout: true).trim()

                    // Print command output line by line
                    echo "cmd_output: ${cmd_output}"
            }
            currentBuild.result = 'SUCCESS'
        }
//        }
//        catch (e)
//        {
//            error "catch ${e}"
//        }
//        finally
//        {
//        }
    }
}