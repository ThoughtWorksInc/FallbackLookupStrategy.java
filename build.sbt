sonatypeProfileName := "com.thoughtworks.spring"

organization := s"${sonatypeProfileName.value}.security.acls.jdbc"

name := "FallbackLookupStrategy"

libraryDependencies += "org.springframework.security" % "spring-security-acl" % "5.1.2.RELEASE"

libraryDependencies += "org.projectlombok" % "lombok" % "1.18.4" % Provided

crossPaths := false
