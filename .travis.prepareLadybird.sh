#!/bin/bash

set +x
set -e

BUILD_LOG=`pwd`/ladybird-build.log
PRINT_EVERY_NTH=10

fetchAndBuild () {
  local PROJECT=$1
  local GITUSER=$2
  local BRANCH=$3
  shift 3

  echo "Project $PROJECT is to be processed." >&2
  echo "Cloning $GITUSER/$PROJECT ..." >&2
  git clone -b $BRANCH https://github.com/$GITUSER/$PROJECT.git 2>&1 | tee -a $BUILD_LOG | sed -n 0~${PRINT_EVERY_NTH}p >&2
  pushd $PROJECT >/dev/null
    for SETVERSION in "$@"; do
      PROPERTY=$(echo $SETVERSION | cut -f1 -d=)
      NEWVERSION=$(echo $SETVERSION | cut -f2 -d=)
      echo "Updating project $PROJECT property version:" >&2
      echo "  -DnewVersion=$NEWVERSION -Dproperty=$PROPERTY" >&2
      sed -e "s/<$PROPERTY>[^<]*<\/$PROPERTY>/<$PROPERTY>$NEWVERSION<\/$PROPERTY>/" -i pom.xml
      # ../mvnw versions:update-property -DallowSnapshots=true -DnewVersion=$NEWVERSION -Dproperty=$PROPERTY  2>&1 | tee -a $BUILD_LOG  | sed -n 0~${PRINT_EVERY_NTH}p >&2
    done
    # deploy
    echo "Building project $PROJECT ..." >&2
    ../mvnw clean install -DskipTests -Dcheckstyle.skip -Denforcer.skip 2>&1 | tee -a $BUILD_LOG | sed -n 0~${PRINT_EVERY_NTH}p >&2
    local PROJECT_VERSION=$(mvn org.apache.maven.plugins:maven-help-plugin:2.1.1:evaluate -Dexpression=project.version 2>/dev/null |grep -Ev '(^\[|Download\w+:)')
    echo "Project $PROJECT version: '$PROJECT_VERSION'" >&2
    echo "Last lines from build log" >&2
    tail -n 50 $BUILD_LOG >&2
    echo $PROJECT_VERSION
  popd >/dev/null
}

echo "NOTE: Just every ${PRINT_EVERY_NTH}th line will be printed for maven and git output."

# build snapshot dependencies
VERSION_ELY=$(fetchAndBuild wildfly-elytron wildfly-security master)
VERSION_ELYWEB=$(fetchAndBuild elytron-web wildfly-security master version.org.wildfly.security.elytron=$VERSION_ELY)
VERSION_ELYTOOL=$(fetchAndBuild wildfly-elytron-tool wildfly-security master version.elytron=$VERSION_ELY)
VERSION_WFCORE=$(fetchAndBuild wildfly-core wildfly-security-incubator ladybird version.org.wildfly.security.elytron=$VERSION_ELY version.org.wildfly.security.elytron.tool=$VERSION_ELYTOOL version.org.wildfly.security.elytron-web.undertow-server=$VERSION_ELYWEB)

# build finally this wildfly branch with checks enabled, but tests disabled
echo "The WildFly is to be processed." >&2
./mvnw versions:update-property -DallowSnapshots=true -DnewVersion=version.org.wildfly.core -Dproperty=$VERSION_WFCORE  2>&1 | tee -a $BUILD_LOG | sed -n 0~10p >&2
sed -i '1s/^/\#\!\/bin\/bash\n/' build.sh
./build.sh clean install -DallTests -DskipTests -Denforcer.skip 2>&1 | tee -a $BUILD_LOG | sed -n 0~10p >&2
echo "Last lines from build log" >&2
tail -n 300 $BUILD_LOG >&2
