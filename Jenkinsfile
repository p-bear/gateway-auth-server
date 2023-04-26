pipeline {
  agent any
  options {
    buildDiscarder(logRotator(numToKeepStr: '3'))
  }
  environment {
    DOCKERHUB_CREDENTIALS = credentials('dockerhub')
    repository = "pbear41/gateway-auth-server"
    dockerImage = ''
    isDockerBuildSuccess = false;
    version_value = ''
    version = ''
    imageName = ''
  }
  stages {
    stage('get version from gradle') {
      steps {
        script {
          version_value = sh(returnStdout: true, script: "cat build.gradle.kts | grep -o 'version = [^,]*'").trim()
          sh "echo Project in version value: $version_value"
          version = version_value.split(/=/)[1].trim().split(/"/)[1].trim()
          sh "echo final version: $version"
          imageName = repository + ":" + version
        }
      }
    }
    stage('get release properties file') {
      steps {
        sh 'cp /mnt/datadisk/data/properties/gateway-auth-server/application-release.yml ./src/main/resources/application-release.yml'
      }
    }
    stage('Gradle Build') {
      steps {
        sh './gradlew clean build'
      }
    }
    stage('Docker Build') {
      steps {
        script {
            sh 'echo imageName: ' + imageName
            dockerImage = docker.build imageName
            isDockerBuildSuccess = true
        }
      }
    }
    stage('Login') {
      steps {
        sh 'echo $DOCKERHUB_CREDENTIALS_PSW | docker login -u $DOCKERHUB_CREDENTIALS_USR --password-stdin'
      }
    }
    stage('Push') {
      steps {
        sh 'docker push ' + imageName
      }
    }
  }
  post {
    always {
      sh 'docker logout'
    }
    success {
      script {
        if (isDockerBuildSuccess == true) {
          sh 'docker rmi ' + imageName
        }
      }
    }
  }
}