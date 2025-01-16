make release RELEASE=1

chmod +x gradlew
./gradlew test
./gradlew build
./gradlew generatePomFileForMavenPublication