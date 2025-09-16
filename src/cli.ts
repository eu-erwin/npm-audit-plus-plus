#!/usr/bin/env node

import { Command } from "commander";
const program = new Command();
import { create } from "xmlbuilder2";

interface Input {
  auditReportVersion?: number; // for version 2 or the audit report
  vulnerabilities?: {
    [key: string]: {
      name: string;
      severity: string;
      isDirect: boolean;
      via: [
        {
          source: string;
          name: string;
          url: string;
          dependency: string;
          title: string;
        }
      ];
      effect: string[];
      range: string;
      nodes: string[];
      fixAvailable: {
        name: string;
        version: string;
        isSemVerMajor: boolean;
      };
    };
  };
  // below is version 1
  metadata: {
    vulnerabilities: {
      critical: number;
      high: number;
      moderate: number;
      low: number;
      info: number;
    };
    dependencies:
      | number
      | {
          prod: number;
          dev: number;
          optional: number;
          peer: number;
          peerOptional: number;
          total: number;
        };
  };
  advisories: {
    [key: string]: {
      findings: {
        version: string;
        paths: string[];
      }[];
      id: number;
      created: string;
      updated: string;
      deleted: string;
      title: string;
      found_by: {
        link: string;
      };
      severity: string;
      module_name: string;
      vulnerable_versions: string;
      overview: string;
      references: string;
    };
  };
}

program
  .name("npm-audit-plus-plus")
  .description(
    "A tool to capture the output of npm audit and convert it to xml"
  )
  .version("1.1.1");

program
  .description("npm audit --json | npx npm-audit-plus-plus")
  .option("--debug", "display debug information")
  .option("-s, --severity [SEVERITY]", "Severity level to treat as error (low, mod, high), default: critical", "critical")
  .action(() => {
    // read the options
    const options = program.opts();

    // read the input
    process.stdin.resume();
    let rawInput = "";
    process.stdin.on("data", (input) => {
      rawInput += input;
    });

    // when input ends, parse the file
    process.stdin.on("end", () => {
      let input: Input;
      try {
        input = JSON.parse(rawInput);
      } catch (e) {
        console.log("Error parsing JSON input");
        console.log(e);
        process.exit(1);
      }
      const critCount = input.metadata.vulnerabilities.critical;
      const highCount = input.metadata.vulnerabilities.high;
      const modCount = input.metadata.vulnerabilities.moderate;
      const lowCount = input.metadata.vulnerabilities.low;
      const infoCount = input.metadata.vulnerabilities.info;
      const depCount = input.metadata.dependencies;

      if (options.debug) {
        console.log(input);
        console.log({
          dependencies: depCount,
          critical: critCount,
          high: highCount,
          moderate: modCount,
          low: lowCount,
          info: infoCount,
        });
      }

      let xml = "";
      if (input.auditReportVersion == 2) {
        if (options.debug) {
          console.log("Using v2");
        }
        xml = v2(input, options.severity);
      } else {
        if (options.debug) {
          console.log("Using v1");
        }
        xml = v1(input, options.severity);
      }
      // when all ok, create success XML and short circuit
      console.log(xml);

      if (critCount > 0) {
        process.exit(1);
      } else {
        process.exit(0);
      }
    });
  });

program.parse(process.argv);

const v1 = (input: Input, severity: "low" | "mod" | "high") => {
  const critCount = input.metadata.vulnerabilities.critical;
  const highCount = input.metadata.vulnerabilities.high;
  const modCount = input.metadata.vulnerabilities.moderate;
  const lowCount = input.metadata.vulnerabilities.low;
  const infoCount = input.metadata.vulnerabilities.info;
  const depCount = input.metadata.dependencies;

  if (
    critCount === 0 &&
    highCount === 0 &&
    modCount === 0 &&
    lowCount === 0 &&
    infoCount === 0
  ) {
    const empty = create({ version: "1.0" })
      .ele("testsuits")
      .ele("testsuite", {
        name: "NPM Audit Summary v1",
        errors: 0,
        failures: 0,
        tests: 1,
      })
      .ele("testcase", {
        classname: "Summary",
        name: `Critical: 0, High: 0, Moderate: 0, Low: 0, Info: 0, Dependencies: ${depCount}`,
      });

    const xml = empty.end({ prettyPrint: true });
    return xml;
  }

  // else, some vulnerabilities were found, create failure XML
  const testcase = [
    {
      "@classname": "Summary",
      "@name": `Critical: ${critCount}, High: ${highCount}, Moderate: ${modCount}, Low: ${lowCount}, Info: ${infoCount}, Dependencies: ${depCount}`,
      "@time": "0",
    },
  ];

  for (const advisory in input.advisories) {
    const failure =
      input.advisories[advisory].severity === "critical"
        ? {
            "@message":
              input.advisories[advisory].title +
              " - " +
              input.advisories[advisory].findings[0].version +
              " - " +
              input.advisories[advisory].findings[0].paths[0],
            "@type": "error",
            "#text": input.advisories[advisory].overview,
          }
        : null;
    testcase.push({
      "@name":
        input.advisories[advisory].title +
        "\n" +
        input.advisories[advisory].overview +
        "\n" +
        input.advisories[advisory].references,
      "@classname":
        input.advisories[advisory].module_name +
        "@" +
        input.advisories[advisory].vulnerable_versions +
        " (" +
        input.advisories[advisory].severity +
        ")",
      failure,
    } as any);
  }

  let errors = critCount;
  switch(severity) {
    case "low":
      errors = lowCount + modCount + highCount + critCount;
      break;
    case "mod":
      errors = modCount + highCount + critCount;
      break;
    case "high":
      errors = highCount + critCount;
      break;
  }

  const obj = {
    testsuites: {
      testsuite: {
        "@name": "NPM Audit Summary",
        "@errors": errors,
        "@failures": errors,
        "@tests": critCount + highCount + modCount + lowCount + infoCount,
        testcase,
      },
    },
  };

  const doc = create(obj);
  const xml = doc.end({ prettyPrint: true });
  return xml;
};

const v2 = (input: Input, severity: "low" | "mod" | "high") => {
  const critCount = input.metadata.vulnerabilities.critical;
  const highCount = input.metadata.vulnerabilities.high;
  const modCount = input.metadata.vulnerabilities.moderate;
  const lowCount = input.metadata.vulnerabilities.low;
  const infoCount = input.metadata.vulnerabilities.info;
  const depCount = (input.metadata.dependencies as any).total;

  if (
    critCount === 0 &&
    highCount === 0 &&
    modCount === 0 &&
    lowCount === 0 &&
    infoCount === 0
  ) {
    const empty = {
      testsuites: {
        testsuite: {
          "@name": "NPM Audit Summary v2",
          "@errors": critCount,
          "@failures": 0,
          "@tests": depCount,
          testcase: {
            "@classname": "Summary",
            "@name": `Critical: ${critCount}, High: ${highCount}, Moderate: ${modCount}, Low: ${lowCount}, Info: ${infoCount}, Dependencies: ${depCount}`,
            "@time": "0",
          },
        },
      },
    };
    const doc = create(empty);
    const xml = doc.end({ prettyPrint: true });
    return xml;
  }

  // when critical vulnerabilities are found, create failure XML
  const testcase = [
    {
      "@classname": "Summary",
      "@name": `Critical: ${critCount}, High: ${highCount}, Moderate: ${modCount}, Low: ${lowCount}, Info: ${infoCount}, Dependencies: ${depCount}`,
      "@time": "0",
    },
  ];

  const vulnerabilities = input.vulnerabilities ?? {};
  for (const vulnerability in vulnerabilities) {
    const failure =
      vulnerabilities[vulnerability].severity === "critical"
        ? {
            "@message":
              vulnerabilities[vulnerability].name +
              " - " +
              (vulnerabilities[vulnerability].effect && vulnerabilities[vulnerability].effect.length > 0 ? vulnerabilities[vulnerability].effect[0] : vulnerabilities[vulnerability].via[0].title),
            "@type": "error",
            "#text":
              vulnerabilities[vulnerability].name +
              " - " +
              vulnerabilities[vulnerability].via[0].name +
              " - " +
              (vulnerabilities[vulnerability].effect && vulnerabilities[vulnerability].effect.length > 0 ? vulnerabilities[vulnerability].effect[0] : vulnerabilities[vulnerability].via[0].title) +
              "\n\nFix available:\n\n" +
              vulnerabilities[vulnerability].fixAvailable.name +
              "@" +
              vulnerabilities[vulnerability].fixAvailable.version,
          }
        : null;

    const viaJoined: string[] = [];
    const via = vulnerabilities[vulnerability].via;
    via.forEach((v) => {
      if (typeof v === "string") {
        viaJoined.push(v);
      } else {
        viaJoined.push(v.title + "\n" + v.url);
      }
    });

    testcase.push({
      "@classname":
        vulnerabilities[vulnerability].name +
        "@" +
        vulnerabilities[vulnerability].range +
        " (" +
        vulnerabilities[vulnerability].severity +
        ")",
      "@name":
        viaJoined.join(" -> ") + vulnerabilities[vulnerability].name,
      "@time": "0",
      failure,
    } as any);
  }

  let errors = critCount;
  switch(severity) {
    case "low":
      errors = lowCount + modCount + highCount + critCount;
      break;
    case "mod":
      errors = modCount + highCount + critCount;
      break;
    case "high":
      errors = highCount + critCount;
      break;
  }

  const root = {
    testsuites: {
      testsuite: {
        "@name": "NPM AUdit Summary v2",
        "@errors": errors,
        "@failures": 0,
        "@tests": depCount,
        testcase,
      },
    },
  };
  const doc = create(root);
  const xml = doc.end({ prettyPrint: true });
  return xml;
};
