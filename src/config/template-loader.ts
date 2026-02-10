/**
 * Template Loading and Merging System
 *
 * Handles resolution of builtin templates, loading YAML files,
 * and deep merging of configuration objects with special array handling.
 */

import * as fs from 'node:fs';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import { parse as parseYaml } from 'yaml';
import type { PartialClawsecConfig } from './schema.js';
import { ConfigLoadError } from './loader.js';
import type { Logger } from '../utils/logger.js';

/**
 * Resolves builtin template names to file paths
 */
export class TemplateResolver {
  private builtinPath: string;
  private logger: Logger;

  constructor(logger: Logger) {
    this.logger = logger;
    // Resolve to rules/builtin/ relative to this file
    // Works from both dist/src/config/ (production) and src/config/ (Vitest)
    const currentDir = path.dirname(fileURLToPath(import.meta.url));
    const fromDist = path.join(currentDir, '../../../rules/builtin');
    const fromSrc = path.join(currentDir, '../../rules/builtin');
    this.builtinPath = fs.existsSync(fromSrc) ? fromSrc : fromDist;
  }

  /**
   * Resolve template name to file path
   * "builtin/aws-security" → "/path/to/rules/builtin/aws-security.yaml"
   */
  resolveTemplatePath(templateName: string): string {
    this.logger.debug(`[Template] Resolving template: ${templateName}`);

    if (templateName.startsWith('builtin/')) {
      const name = templateName.replace('builtin/', '');
      const filePath = path.join(this.builtinPath, `${name}.yaml`);

      this.logger.debug(`[Template] Checking builtin path: ${filePath}`);

      // Check if file exists
      if (!fs.existsSync(filePath)) {
        this.logger.error(`[Template] Template not found: ${templateName} at ${filePath}`);
        throw new ConfigLoadError(
          `Built-in template not found: ${templateName}`,
          filePath
        );
      }

      this.logger.info(`[Template] Loaded builtin template: ${templateName}`);
      return filePath;
    }

    // Assume it's a file path
    this.logger.debug(`[Template] Resolving custom template path: ${templateName}`);
    return path.resolve(templateName);
  }

  /**
   * Load a single template file
   */
  loadTemplate(templateName: string): PartialClawsecConfig {
    this.logger.debug(`[Template] Loading template: ${templateName}`);
    const filePath = this.resolveTemplatePath(templateName);

    try {
      const content = fs.readFileSync(filePath, 'utf-8');
      const parsed = parseYaml(content) as PartialClawsecConfig;

      this.logger.debug(`[Template] Parsed template ${templateName}, removing metadata fields`);

      // Remove template metadata fields (name, description, version)
      // These are for documentation only
      if (parsed && typeof parsed === 'object') {
        delete (parsed as Record<string, unknown>).name;
        delete (parsed as Record<string, unknown>).description;
      }

      this.logger.info(`[Template] Successfully loaded template: ${templateName}`);
      return parsed || {};
    } catch (error) {
      this.logger.error(`[Template] Failed to load template ${templateName}: ${error instanceof Error ? error.message : String(error)}`);
      throw new ConfigLoadError(
        `Failed to load template ${templateName}: ${error instanceof Error ? error.message : String(error)}`,
        filePath,
        error instanceof Error ? error : undefined
      );
    }
  }
}

/**
 * Deep merge arrays by concatenating them and removing duplicates
 * For patterns arrays: [...templatePatterns, ...userPatterns]
 */
function mergeArrays<T>(target: T[], source: T[]): T[] {
  // Remove duplicates while preserving order
  const combined = [...target, ...source];
  return Array.from(new Set(combined));
}

/**
 * Deep merge two configs, with special handling for arrays
 */
export function deepMergeConfigs(
  target: PartialClawsecConfig = {},
  source: PartialClawsecConfig = {}
): PartialClawsecConfig {
  const result: Record<string, unknown> = { ...target };

  for (const [key, sourceValue] of Object.entries(source || {})) {
    const targetValue = result[key];

    // Array merging: concatenate and dedupe
    if (Array.isArray(sourceValue) && Array.isArray(targetValue)) {
      result[key] = mergeArrays(targetValue, sourceValue);
    }
    // Object merging: recurse
    else if (
      isPlainObject(sourceValue) &&
      isPlainObject(targetValue)
    ) {
      result[key] = deepMergeConfigs(
        targetValue as PartialClawsecConfig,
        sourceValue as PartialClawsecConfig
      );
    }
    // Value override: source wins
    else if (sourceValue !== undefined) {
      result[key] = sourceValue;
    }
  }

  return result as PartialClawsecConfig;
}

/**
 * Check if value is a plain object (not array, not null)
 */
function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

/**
 * Load and merge multiple templates in order
 */
export function loadTemplates(templateNames: string[], logger: Logger): PartialClawsecConfig {
  logger.info(`[Template] Loading ${templateNames.length} templates: ${templateNames.join(', ')}`);
  const resolver = new TemplateResolver(logger);
  let merged: PartialClawsecConfig = {};

  for (const templateName of templateNames) {
    const template = resolver.loadTemplate(templateName);
    merged = deepMergeConfigs(merged, template);
    logger.debug(`[Template] Merged template ${templateName} into config`);
  }

  logger.info(`[Template] All templates loaded and merged successfully`);
  return merged;
}
