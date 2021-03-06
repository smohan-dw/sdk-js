/**
 * Config is used to configure logging.
 *
 * @packageDocumentation
 * @ignore
 * @preferred
 */

import {
  LFService,
  LoggerFactoryOptions,
  LogGroupRule,
  LogLevel,
  getLogControl,
  LogGroupControlSettings,
} from 'typescript-logging'

// Create options instance and specify 1 LogGroupRule:
// * LogLevel Error on default, env DEBUG = 'true' changes Level to Debug.
const options = new LoggerFactoryOptions().addLogGroupRule(
  new LogGroupRule(
    new RegExp('.+'),
    process.env.DEBUG && process.env.DEBUG === 'true'
      ? LogLevel.Debug
      : LogLevel.Error
  )
)
// Create a named loggerfactory and pass in the options and export the factory.
// Named is since version 0.2.+ (it's recommended for future usage)
// eslint-disable-next-line import/prefer-default-export
export const factory = LFService.createNamedLoggerFactory(
  'LoggerFactory',
  options
)

/**
 *  Changes all existing Loggers of our default Factory with id 0 to the intended Level.
 *
 * @param level The intended LogLevel. LogLevel has a range of 0 to 5.
 */
export function modifyLogLevel(level: LogLevel): void {
  let actualLevel
  if (level < 0) {
    actualLevel = 0
  } else if (level > 5) {
    actualLevel = 5
  } else actualLevel = level
  getLogControl()
    .getLoggerFactoryControl(0)
    .change({
      group: 'all',
      logLevel: LogLevel[actualLevel],
    } as LogGroupControlSettings)
}
