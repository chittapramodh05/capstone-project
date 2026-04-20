pipeline {
    agent any

    environment {
        // Define docker-compose path if necessary, or let Jenkins pick it from system PATH.
        COMPOSE_EXE = 'docker compose'
    }

    stages {
        stage('Checkout') {
            steps {
                echo 'Checking out code from source repository...'
                checkout scm
            }
        }

        stage('Verify Environment') {
            steps {
                echo 'Verifying Docker and Docker Compose availability...'
                bat 'docker --version'
                bat "${COMPOSE_EXE} version"
            }
        }

        stage('Build Docker Images') {
            steps {
                echo 'Building Docker images for ML API, Backend, and Frontend...'
                bat "${COMPOSE_EXE} build"
            }
        }

        stage('Deploy/Run Containers') {
            steps {
                echo 'Creating required .env file for backend...'
                bat 'echo PORT=5000 > backend\\.env'
                bat 'echo MONGO_URI=mongodb://mongodb:27017/agenticDB >> backend\\.env'
                bat 'echo JWT_SECRET=supersecretkey123 >> backend\\.env'
                bat 'echo JWT_REFRESH_SECRET=supersecretrefresh >> backend\\.env'

                echo 'Starting up containers in detached mode...'
                bat "${COMPOSE_EXE} up -d"
            }
        }

        stage('Health Check') {
            steps {
                echo 'Awaiting few seconds for services to properly start...'
                sleep 5
                
                echo 'Checking running containers...'
                bat 'docker ps'
                
                echo 'Verifying frontend response...'
                bat 'curl -f http://localhost:5173 || exit 1'
                
                echo 'Verifying ml-api response...'
                bat 'curl -f http://localhost:8000/ || exit 1'
            }
        }
    }

    post {
        always {
            echo 'Pipeline finished. Tearing down services to free up port/resources (optional for actual CD, good for CI testing).'
            // bat "${COMPOSE_EXE} down"
        }
        success {
            echo 'All stages completed successfully. Application is healthy!'
        }
        failure {
            echo 'Pipeline failed. Please check logs.'
        }
    }
}
