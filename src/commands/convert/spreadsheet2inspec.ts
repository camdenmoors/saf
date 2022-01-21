import {Command, flags} from '@oclif/command'
import fs from 'fs'
import path from 'path'
import parse from 'csv-parse/lib/sync'
import {InSpecControl, InSpecMetaData} from '../../types/inspec'
import YAML from 'yaml'
import XlsxPopulate from 'xlsx-populate'
import {impactNumberToSeverityString, inspecControlToRubyCode} from '../../utils/xccdf2inspec'
import _ from 'lodash'
import {CSVControl} from '../../types/csv'
import {extractValueViaPathOrNumber, findFieldIndex, getInstalledPath} from '../../utils/global'
import {default as CCINistMappings} from '@mitre/hdf-converters/lib/data/cci-nist-mapping.json'
import {default as CISNistMappings} from '../../resources/cis2nist.json'

export default class Spreadsheet2HDF extends Command {
  static usage = 'convert:spreadsheet2inspec -i, --input=<XLSX or CSV> -o, --output=FOLDER'

  static description = 'Convert CSV STIGs or CIS XLSX benchmarks into a skeleton InSpec profile'

  static examples = ['saf convert:spreadsheet2inspec -i spreadsheet.xlsx -o profile']

  static flags = {
    help: flags.help({char: 'h'}),
    input: flags.string({char: 'i', required: true}),
    controlNamePrefix: flags.string({char: 'c', required: false, default: '', description: 'Prefix for all control IDs'}),
    metadata: flags.string({char: 'm', required: false, description: 'Path to a JSON file with additional metadata for the inspec.yml file'}),
    mapping: flags.string({char: 'M', required: false, description: 'Path to a YAML file with mappings for each field, by default, CIS Benchmark fields are used for XLSX, STIG Viewer CSV export is used by CSV'}),
    severity: flags.string({char: 's', required: false, description: 'Control severity level', default: '0.5', options: ['0.0', '0.1', '0.4', '0.7', '0.9', '1.0']}),
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
    let mappings: Record<string, string | number> = {}

    // Read metadata file if passed
    if (flags.metadata) {
      if (fs.existsSync(flags.metadata)) {
        metadata = JSON.parse(fs.readFileSync(flags.metadata, 'utf-8'))
      } else {
        throw new Error('Passed metadata file does not exist')
      }
    }

    const inspecControls: InSpecControl[] = []

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

    await XlsxPopulate.fromFileAsync(flags.input).then((workBook: any) => {
      const targetSheets = [1, 2]
      const completedIds: string[] = [] // Numbers such as 1.10 can get parsed 1.1 which will over-write controls, keep track of existing controls to prevent this
      // Read mapping file
      if (flags.mapping) {
        if (fs.existsSync(flags.mapping)) {
          mappings = YAML.parse(fs.readFileSync(flags.mapping, 'utf-8'))
        } else {
          throw new Error('Passed metadata file does not exist')
        }
      } else {
        mappings = YAML.parse(fs.readFileSync(path.join(getInstalledPath(), 'src', 'resources', 'xlsx.mapping.yml'), 'utf-8'))
      }

      targetSheets.forEach(targetSheet => {
        const sheet = workBook.sheet(targetSheet)
        const usedRange = sheet.usedRange()
        if (usedRange) {
          const extractedData: (string | number)[][] = usedRange.value()
          const headers = extractedData[0]
          const recommendationNumberIndex = findFieldIndex(mappings.id.toString(), headers, 1)
          const titleIndex = findFieldIndex(mappings.title.toString(), headers, 2)
          const descriptionIndex = findFieldIndex(mappings.desc.toString(), headers, 5)
          const rationaleStatementIndex = findFieldIndex(mappings.rationale.toString(), headers, 6)
          const remediationProcedureIndex = findFieldIndex(mappings['tags.fix'].toString(), headers, 7)
          const auditProcedureIndex = findFieldIndex(mappings['tags.check'].toString(), headers, 8)
          const cisControlsIndex = findFieldIndex(mappings['tags.cis'].toString(), headers, 11)

          // Convert controls
          extractedData.slice(1).forEach((control: (string | number)[]) => {
            if (control[recommendationNumberIndex]) {
            // Ensure no duplicate control IDs are handled
              let controlId = control[recommendationNumberIndex].toString()
              while (completedIds.indexOf(controlId) !== -1) {
                controlId += '0'
              }
              completedIds.push(controlId)
              // Extract control info
              const inspecControl: InSpecControl = {
                id: `${flags.controlNamePrefix ? flags.controlNamePrefix + '-' : ''}${controlId}`,
                title: (control[titleIndex] || '').toString(),
                desc: (control[descriptionIndex] || '').toString(),
                rationale: (control[rationaleStatementIndex] || '').toString(),
                impact: mappings.severity as number,
                tags: {
                  nist: [],
                  check: (control[auditProcedureIndex] || '').toString(),
                  fix: (control[remediationProcedureIndex] || '').toString(),
                  severity: impactNumberToSeverityString(Number.parseFloat(flags.severity)),
                  cis_level: (targetSheet || '').toString(),
                  cis_rid: controlId,
                  cis_controls: [],
                },
              }
              if (control[cisControlsIndex]) {
                const cisControls = control[cisControlsIndex].toString().match(/CONTROL:v(\d) (\d+)\.?(\d*)/g)
                if (cisControls) {
                  cisControls.map(cisControl => cisControl.split(' ')).forEach(([revision, cisControl]) => {
                    const controlRevision = revision.split('CONTROL:v')[1]
                  inspecControl.tags.cis_controls?.push(cisControl, `Rev_${controlRevision}`)
                  if (cisControl in CISNistMappings) {
                    inspecControl.tags.nist?.push(_.get(CISNistMappings, cisControl))
                  }
                  })
                }
              }
              inspecControls.push(inspecControl)
            }
          })
        }
      })
    }).catch(error => {
      console.log(error)
      // Assume we have a CSV file
      // Read the input file into lines
      const inputDataLines = fs.readFileSync(flags.input, 'utf-8').split('\n')
      // Replace BOM if it exists
      inputDataLines[0] = inputDataLines[0].replace(/\uFEFF/g, '')
      // STIG Viewer embeds the classification level in the first and last line for CSV export, breaking parsing
      if (inputDataLines[0].match(/~~~~~.*~~~~~/)?.length) {
        inputDataLines.shift()
      }
      if (inputDataLines[inputDataLines.length - 1].match(/~~~~~.*~~~~~/)?.length) {
        inputDataLines.pop()
      }

      // Read mapping file
      if (flags.mapping) {
        if (fs.existsSync(flags.mapping)) {
          mappings = YAML.parse(fs.readFileSync(flags.mapping, 'utf-8'))
        } else {
          throw new Error('Passed metadata file does not exist')
        }
      } else {
        mappings = YAML.parse(fs.readFileSync(path.join(getInstalledPath(), 'src', 'resources', 'csv.mapping.yml'), 'utf-8'))
      }

      const records: CSVControl[] = parse(inputDataLines.join('\n'), {
        columns: true,
        skip_empty_lines: true,
      })

      records.forEach(record => {
        const newControl: Partial<InSpecControl> = {
          tags: {
            nist: [],
            severity: impactNumberToSeverityString(extractValueViaPathOrNumber('mappings.impact', mappings.impact, record)),
          },
        }
        Object.entries(mappings).forEach(mapping => {
          if (mapping[0] === 'title' && flags.controlNamePrefix) {
            _.set(newControl, mapping[0].toLowerCase(), `${flags.controlNamePrefix ? flags.controlNamePrefix + '-' : ''}${extractValueViaPathOrNumber(mapping[0], mapping[1], record)}`)
          }
          _.set(newControl, mapping[0].toLowerCase(), extractValueViaPathOrNumber(mapping[0], mapping[1], record))
        })
        if (newControl.tags && newControl.tags?.cci) {
          newControl.tags.nist = []
          newControl.tags.cci.forEach(cci => {
            if (cci in CCINistMappings) {
              newControl.tags?.nist?.push(_.get(CCINistMappings, cci))
            }
          })
        }
        inspecControls.push(newControl as unknown as InSpecControl)
      })
    })

    // Convert all extracted controls to Ruby/InSpec code
    inspecControls.forEach(control => {
      fs.writeFileSync(path.join(flags.output, 'controls', control.id + '.rb'), inspecControlToRubyCode(control))
    })
  }
}
