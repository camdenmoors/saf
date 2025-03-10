import parser from 'fast-xml-parser'
import * as htmlparser from 'htmlparser2'
import _ from 'lodash'
import {InSpecControl} from '../types/inspec'
import {DecodedDescription} from '../types/xccdf'

const wrap = (s: string) => s.replace(
  /(?![^\n]{1,80}$)([^\n]{1,80})\s/g, '$1\n'
)

const escape = (s: string) => s.replace(/\\/g, '\\\\').replace(/'/g, '\\\'')
const escapeQuotes = (s: string) => s.replace(/\\/g, '\\\\').replace(/"/g, '\\"')

const wrapAndEscape = (s: string) => escape(wrap(s))
const wrapAndEscapeQuotes = (s: string) => escapeQuotes(wrap(s))

export function convertEncodedXmlIntoJson(
  encodedXml: string
): any {
  return parser.parse(encodedXml, {
    ignoreAttributes: false,
    attributeNamePrefix: '@_',
  })
}

export function convertEncodedHTMLIntoJson(encodedHTML?: string): DecodedDescription {
  if (encodedHTML) {
    // Some STIGs regarding XSS put the < character inside of the description which breaks parsing
    const patchedHTML = encodedHTML.replace(/"&lt;"/g, '[[[REPLACE_LESS_THAN]]]')

    const xmlChunks: string[] = []
    const htmlParser = new htmlparser.Parser({
      ontext(text: string) {
        xmlChunks.push(text)
      },
    })
    htmlParser.write(patchedHTML)
    htmlParser.end()
    const converted = convertEncodedXmlIntoJson(xmlChunks.join(''))
    let cleaned: Record<string, string | boolean | undefined> = {}

    if (typeof converted.VulnDiscussion === 'object') { // Some STIGs have xml tags inside of the actual text which breaks processing, e.g U_ASD_STIG_V5R1_Manual-xccdf.xml and all Oracle Database STIGs
      let extractedVulnDescription = ''
      const remainingFields = _.omit(converted.VulnDiscussion, ['FalsePositives', 'FalseNegatives', 'Documentable', 'Mitigations', 'SeverityOverrideGuidance', 'PotentialImpacts', 'ThirdPartyTools', 'MitigationControl', 'Responsibility', 'IAControls'])
      Object.entries(remainingFields).forEach(async ([field, value]) => {
        extractedVulnDescription += `<${field}> ${value}`
      })
      cleaned = {
        VulnDiscussion: extractedVulnDescription.replace(/\[\[\[REPLACE_LESS_THAN]]]/, '"<"'),
      }
      Object.entries(converted.VulnDiscussion).forEach(async ([key, value]) => {
        if (typeof value === 'string') {
          cleaned[key] = (value as string).replace(/\[\[\[REPLACE_LESS_THAN]]]/, '"<"')
        } else {
          cleaned[key] = (value as boolean)
        }
      })
    } else {
      Object.entries(converted).forEach(async ([key, value]) => {
        if (typeof value === 'string') {
          cleaned[key] = (value as string).replace(/\[\[\[REPLACE_LESS_THAN]]]/, '"<"')
        } else {
          cleaned[key] = (value as boolean)
        }
      })
    }
    return cleaned
  }
  return {}
}

export function severityStringToImpact(string: string): number {
  if (string.match(/none|na|n\/a|not[\s()*_|]?applicable/i)?.length) {
    return 0.0
  }
  if (string.match(/low|cat(egory)?\s*(iii|3)/i)?.length) {
    return 0.3
  }
  if (string.match(/med(ium)?|cat(egory)?\s*(ii|2)/)?.length) {
    return 0.5
  }
  if (string.match(/high|cat(egory)?\s*(i|1)/)?.length) {
    return 0.7
  }
  if (string.match(/crit(ical)?|severe/)?.length) {
    return 1.0
  }
  throw new Error(`${string}' is not a valid severity value. It should be one of the approved keywords`)
}

export function impactStringToSeverity(impact: number): string {
  if (impact < 0.0 || impact > 1.0) {
    throw new Error('Impact cannot be less than 0.0 or greater than 1.0')
  } else {
    if (impact >= 0.9) {
      return 'critical'
    }
    if (impact >= 0.7) {
      return 'high'
    }
    if (impact >= 0.4) {
      return 'medium'
    }
    if (impact >= 0.1) {
      return 'low'
    }
    return 'none'
  }
}

export function inspecControlToRubyCode(control: InSpecControl): string {
  let result = '# encoding: UTF-8\n\n'
  result += `control '${control.id}' do\n`
  result += `  title '${wrapAndEscape(control.title)}'\n`
  result += `  desc '${wrapAndEscape(control.desc)}'\n`
  result += `  desc 'rationale' '${wrapAndEscape(control.rationale)}'\n`
  if (control.tags.check) {
    result += `  desc 'check' "${wrapAndEscapeQuotes(control.tags.check)}"\n`
  }
  if (control.tags.fix) {
    result += `  desc 'fix' "${wrapAndEscapeQuotes(control.tags.fix)}"\n`
  }
  result += `  impact ${control.impact}\n`
  Object.entries(control.tags).forEach(([tag, value]) => {
    if (tag !== 'check' && tag !== 'fix' && value) {
      if (typeof value === 'object') {
        result += `  tag ${tag}: ${JSON.stringify(value)}\n`
      } else if (typeof value === 'string') {
        result += `  tag ${tag}: '${wrapAndEscape(value)}'\n`
      }
    }
  })
  result += 'end'
  return result
}
