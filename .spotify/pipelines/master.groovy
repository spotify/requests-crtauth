@Grab(group='com.spotify', module='pipeline-conventions', version='1.0.3-SNAPSHOT')
import com.spotify.pipeline.Pipeline
import javaposse.jobdsl.dsl.Job


new Pipeline(this) {{ build {
  notify.byMail(recipients: 'alf+build@spotify.com')

  group(name: 'Test') {
    jenkinsPipeline.inJob {
      jenkinsPipeline.inSteps {
        shell(readFileFromWorkspace('.spotify/pipelines/tox.sh'))
      }
          failNoReports true
          lineTarget(80, 80, 80)
        }
      }
    }
  }
  group(name: 'PyPi Build & Upload') {
    jenkinsPipeline.inJob {
      jenkinsPipeline.inSteps {
        shell(readFileFromWorkspace('.spotify/pipelines/release.sh'))
      }
    }
  }

}}}
