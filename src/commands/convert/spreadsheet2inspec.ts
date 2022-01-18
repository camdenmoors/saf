import {Command, flags} from '@oclif/command'
import fs from 'fs'
import path from 'path'
import {InSpecControl, InSpecMetaData} from '../../types/inspec'
import YAML from 'yaml'
import XlsxPopulate from 'xlsx-populate'
import {inspecControlToRubyCode} from '../../utils/xccdf2inspec'
import _ from 'lodash'

const findFieldIndex = (field: string, fields: (string | number)[]) => field in fields ? fields.indexOf(field) : undefined

export default class Spreadsheet2HDF extends Command {
  static usage = 'convert:spreadsheet2inspec -i, --input=<XLSX or CSV> -o, --output=FOLDER'

  static description = 'Pull SonarQube vulnerabilities for the specified project name from an API and convert into a Heimdall Data Format JSON file'

  static examples = ['saf convert:sonarqube2hdf -n sonar_project_key -u http://sonar:9000 --auth YOUR_API_KEY -o scan_results.json']

  static flags = {
    help: flags.help({char: 'h'}),
    input: flags.string({char: 'i', required: true}),
    controlNamePrefix: flags.string({char: 'c', required: false, default: '', description: 'Prefix for all control IDs'}),
    metadata: flags.string({char: 'm', required: false, description: 'Path to a JSON file with additional metadata for the inspec.yml file'}),
    singleFile: flags.boolean({char: 's', required: false, default: false, description: 'Output the resulting controls as a single file'}),
    sheetName: flags.string({char: 'S', required: false, default: 'cis', description: 'Sheet containing controls (for XLSX input)'}),
    output: flags.string({char: 'o', required: true}),
  }

  async run() {
    const {flags} = this.parse(Spreadsheet2HDF)

    // Check if the output folder already exists
    if (fs.existsSync(flags.output)) {
      // Folder should not exist already
      // throw new Error('Profile output folder already exists, please specify a new folder')
      console.log('1')
    } else {
      fs.mkdirSync(flags.output)
      fs.mkdirSync(path.join(flags.output, 'controls'))
      fs.mkdirSync(path.join(flags.output, 'libraries'))
    }
    let metadata: InSpecMetaData = {}
    // Read metadata file if passed
    if (flags.metadata) {
      if (fs.existsSync(flags.metadata)) {
        metadata = JSON.parse(fs.readFileSync(flags.metadata, 'utf-8'))
      } else {
        throw new Error('Passed metadata file does not exist')
      }
    }

    const inspecControls: InSpecControl[] = []

    await XlsxPopulate.fromFileAsync(flags.input).then((workBook: any) => {
      const targetSheets = [1, 2]
      const completedIds: string[] = [] // Numbers such as 1.10 can get parsed 1.1 which will over-write controls, keep track of existing controls to prevent this
      targetSheets.forEach(targetSheet => {
        const sheet = workBook.sheet(targetSheet)
        const extractedData: (string | number)[][] = sheet.usedRange().value()
        const headers = extractedData[0]
        const sectionNumberIndex = findFieldIndex('section #', headers) || 0
        const recommendationNumberIndex = findFieldIndex('recommendation #', headers) || 1
        const titleIndex = findFieldIndex('title', headers) || 2
        const statusIndex = findFieldIndex('status', headers) || 3
        const scoringStatusIndex = findFieldIndex('scoring status', headers) || 4
        const descriptionIndex = findFieldIndex('description', headers) || 5
        const rationaleStatementIndex = findFieldIndex('rationale statement', headers) || 6
        const remediationProcedureIndex = findFieldIndex('remediation procedure', headers) || 7
        const auditProcedureIndex = findFieldIndex('audit procedure', headers) || 8
        const impactStatementIndex = findFieldIndex('impact statement', headers) || 9
        const notesIndex = findFieldIndex('notes', headers) || 10
        const cisControlsIndex = findFieldIndex('CIS controls', headers) || 11
        const cceIDIndex = findFieldIndex('CCE-ID', headers) || 12
        const referencesIndex = findFieldIndex('references', headers) || 13

        // Convert profile inspec.yml
        const profileInfo: Record<string, string | number | undefined> = {
          name: 'CIS Benchmark',
          title: 'InSpec Profile',
          maintainer: metadata.maintainer || 'The Authors',
          copyright: metadata.copyright || 'The Authors',
          copyright_email: metadata.copyright_email || 'you@example.com',
          license: metadata.license || 'Apache-2.0',
          summary: '"An InSpec Compliance Profile"',
          version: metadata.version || '0.1.0',
        }
        fs.writeFileSync(path.join(flags.output, 'inspec.yml'), YAML.stringify(profileInfo))

        // Write README.md
        const readableMetadata: Record<string, string | number> = {}
        Object.entries(profileInfo).forEach(async ([key, value]) => {
        // Filter out any undefined values and omit summary and title
          if (value && key !== 'summary' && key !== 'summary') {
            readableMetadata[_.startCase(key)] = value
          }
        })
        fs.writeFileSync(path.join(flags.output, 'README.md'), `# ${profileInfo.name}\n${profileInfo.summary}\n---\n${YAML.stringify(readableMetadata)}`)

        // Convert controls
        extractedData.slice(1).forEach((control: (string | number)[]) => {
          if (control[recommendationNumberIndex]) {
            // Ensure no duplicate control IDs are handled
            let controlId = control[recommendationNumberIndex].toString()
            while (completedIds.indexOf(controlId) !== -1) {
              console.log(controlId)
              controlId += '0'
            }
            completedIds.push(controlId)
            // Extract control info
            const inspecControl: InSpecControl = {
              id: `${flags.controlNamePrefix ? flags.controlNamePrefix + '-' : ''}${controlId}`,
              title: control[titleIndex].toString(),
              desc: control[descriptionIndex].toString(),
              rationale: control[rationaleStatementIndex].toString(),
              impact: targetSheet === 1 ? 0.5 : 0.7,
              tags: {
                check: control[auditProcedureIndex].toString(),
                severity: targetSheet === 1 ? 'medium' : 'high',
              },
            }
            // if (control[cisControlsIndex]) {
            //   console.log(control[cisControlsIndex].toString().match(/CONTROL:v(\d) (\d+)\.?(\d*)/g))
            // }
            inspecControls.push(inspecControl)
          }
        })
      })
    }).catch((error: any) => {
      console.log(error)
    })

    // Convert all extracted controls to Ruby/InSpec code
    if (flags.singleFile) {
      const controlOutfile = fs.createWriteStream(path.join(flags.output, 'controls', 'controls.rb'), {flags: 'w'})
      inspecControls.forEach(async control => {
        controlOutfile.write(inspecControlToRubyCode(control) + '\n\n')
      })
      controlOutfile.close()
    } else {
      inspecControls.forEach(control => {
        fs.writeFileSync(path.join(flags.output, 'controls', control.id + '.rb'), inspecControlToRubyCode(control))
      })
    }
  }
}
