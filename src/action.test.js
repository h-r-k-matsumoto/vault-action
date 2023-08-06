jest.mock('got');
jest.mock('@actions/core');
jest.mock('@actions/core/lib/command');
jest.mock('./ghsecrets');

const command = require('@actions/core/lib/command');
const core = require('@actions/core');
const got = require('got');
const {
    exportSecrets,
    parseSecretsInput,
    parseHeadersInput
} = require('./action');
const ghsecrets= require('./ghsecrets');

const { when } = require('jest-when');

describe('parseSecretsInput', () => {
    it('parses simple secret', () => {
        const output = parseSecretsInput('test key');
        expect(output).toContainEqual({
            path: 'test',
            selector: 'key',
            outputVarName: 'key',
            envVarName: 'KEY'
        });
    });

    it('parses mapped secret', () => {
        const output = parseSecretsInput('test key|testName');
        expect(output).toHaveLength(1);
        expect(output[0]).toMatchObject({
            outputVarName: 'testName',
            envVarName: 'testName',
        });
    });

    it('fails on invalid mapped name', () => {
        expect(() => parseSecretsInput('test key|'))
            .toThrowError(`You must provide a value when mapping a secret to a name. Input: "test key|"`)
    });

    it('fails on invalid path for mapped', () => {
        expect(() => parseSecretsInput('|testName'))
            .toThrowError(`You must provide a valid path and key. Input: "|testName"`)
    });

    it('parses multiple secrets', () => {
        const output = parseSecretsInput('first a;second b;');

        expect(output).toHaveLength(2);
        expect(output[0]).toMatchObject({
            path: 'first',
        });
        expect(output[1]).toMatchObject({
            path: 'second',
        });
    });

    it('parses multiple complex secret input', () => {
        const output = parseSecretsInput('first a;second b|secondName');

        expect(output).toHaveLength(2);
        expect(output[0]).toMatchObject({
            outputVarName: 'a',
            envVarName: 'A',
        });
        expect(output[1]).toMatchObject({
            outputVarName: 'secondName',
            envVarName: 'secondName'
        });
    });

    it('parses multiline input', () => {
        const output = parseSecretsInput(`
        first a;
        second b;
        third c | SOME_C;`);

        expect(output).toHaveLength(3);
        expect(output[0]).toMatchObject({
            path: 'first',
        });
        expect(output[1]).toMatchObject({
            outputVarName: 'b',
            envVarName: 'B'
        });
        expect(output[2]).toMatchObject({
            outputVarName: 'SOME_C',
            envVarName: 'SOME_C',
        });
    });
});

describe('parseHeaders', () => {
    it('parses simple header', () => {
        when(core.getInput)
            .calledWith('extraHeaders', undefined)
            .mockReturnValueOnce('TEST: 1');
        const result = parseHeadersInput('extraHeaders');
        expect(Array.from(result)).toContainEqual(['test', '1']);
    });

    it('parses simple header with whitespace', () => {
        when(core.getInput)
            .calledWith('extraHeaders', undefined)
            .mockReturnValueOnce(`
            TEST: 1
            `);
        const result = parseHeadersInput('extraHeaders');
        expect(Array.from(result)).toContainEqual(['test', '1']);
    });

    it('parses multiple headers', () => {
        when(core.getInput)
            .calledWith('extraHeaders', undefined)
            .mockReturnValueOnce(`
            TEST: 1
            FOO: bAr
            `);
        const result = parseHeadersInput('extraHeaders');
        expect(Array.from(result)).toContainEqual(['test', '1']);
        expect(Array.from(result)).toContainEqual(['foo', 'bAr']);
    });

    it('parses null response', () => {
        when(core.getInput)
            .calledWith('extraHeaders', undefined)
            .mockReturnValueOnce(null);
        const result = parseHeadersInput('extraHeaders');
        expect(Array.from(result)).toHaveLength(0);
    });
});

describe('exportSecrets', () => {
    beforeEach(() => {
        jest.resetAllMocks();

        when(core.getInput)
            .calledWith('url', expect.anything())
            .mockReturnValueOnce('http://vault:8200');

        when(core.getInput)
            .calledWith('token', expect.anything())
            .mockReturnValueOnce('EXAMPLE');
    });

    function mockInput(key) {
        when(core.getInput)
            .calledWith('secrets', expect.anything())
            .mockReturnValueOnce(key);
    }

    function mockVersion(version) {
        when(core.getInput)
            .calledWith('kv-version', expect.anything())
            .mockReturnValueOnce(version);
    }

    function mockExtraHeaders(headerString) {
        when(core.getInput)
            .calledWith('extraHeaders', expect.anything())
            .mockReturnValueOnce(headerString);
    }

    function mockVaultData(data, version='2') {
        switch(version) {
            case '1':
                got.extend.mockReturnValue({
                    get: async () => ({ body: JSON.stringify({ data }) })
                });
            break;
            case '2':
                got.extend.mockReturnValue({
                    get: async () => ({ body: JSON.stringify({ data: {
                        data
                    } }) })
                });
            break;
        }
    }

    function mockExportToken(doExport) {
        when(core.getInput)
            .calledWith('exportToken', expect.anything())
            .mockReturnValueOnce(doExport);
    }

    function mockOutputToken(doOutput) {
      when(core.getInput)
          .calledWith('outputToken', expect.anything())
          .mockReturnValueOnce(doOutput);
  }
    function mockEncodeType(doEncode) {
        when(core.getInput)
            .calledWith('secretEncodingType', expect.anything())
            .mockReturnValueOnce(doEncode);
    }

    it('simple secret retrieval', async () => {
        mockInput('test key');
        mockVaultData({
            key: 1
        });

        await exportSecrets();

        expect(core.exportVariable).toBeCalledWith('KEY', '1');
        expect(core.setOutput).toBeCalledWith('key', '1');
    });

    it('encoded secret retrieval', async () => {
        mockInput('test key');
        mockVaultData({
            key: 'MQ=='
        });
        mockEncodeType('base64');

        await exportSecrets();

        expect(core.exportVariable).toBeCalledWith('KEY', '1');
        expect(core.setOutput).toBeCalledWith('key', '1');
    });

    it('JSON data secret retrieval', async () => {
        const jsonData = {"x":1,"y":2};

        let result = JSON.stringify(jsonData);

        mockInput('test key');
        mockVaultData({
            key: jsonData,
        });

        await exportSecrets();

        expect(core.exportVariable).toBeCalledWith('KEY', result);
        expect(core.setOutput).toBeCalledWith('key', result);
    });

    it('JSON string secret retrieval', async () => {
        const jsonString = '{"x":1,"y":2}';

        mockInput('test key');
        mockVaultData({
            key: jsonString,
        });

        await exportSecrets();

        expect(core.exportVariable).toBeCalledWith('KEY', jsonString);
        expect(core.setOutput).toBeCalledWith('key', jsonString);
    });

    it('multi-line JSON string secret retrieval', async () => {
        const jsonString = `
        {
            "x":1,
            "y":"bar"
        }
        `;

        mockInput('test key');
        mockVaultData({
            key: jsonString,
        });

        await exportSecrets();

        expect(core.exportVariable).toBeCalledWith('KEY', jsonString);
        expect(core.setOutput).toBeCalledWith('key', jsonString);
    });

    it('intl secret retrieval', async () => {
        mockInput('测试 测试');
        mockVaultData({
            测试: 1
        });

        await exportSecrets();

        expect(core.exportVariable).toBeCalledWith('测试', '1');
        expect(core.setOutput).toBeCalledWith('测试', '1');
    });

    it('mapped secret retrieval', async () => {
        mockInput('test key|TEST_NAME');
        mockVaultData({
            key: 1
        });

        await exportSecrets();

        expect(core.exportVariable).toBeCalledWith('TEST_NAME', '1');
        expect(core.setOutput).toBeCalledWith('TEST_NAME', '1');
    });

    it('simple secret retrieval from K/V v1', async () => {
        const version = '1';

        mockInput('test key');
        mockExtraHeaders(`
        TEST: 1
        `);
        mockVaultData({
            key: 1
        });

        await exportSecrets();

        expect(core.exportVariable).toBeCalledWith('KEY', '1');
        expect(core.setOutput).toBeCalledWith('key', '1');
    });

    it('simple secret retrieval with extra headers', async () => {
        const version = '1';

        mockInput('test key');
        mockVersion(version);
        mockVaultData({
            key: 1
        }, version);

        await exportSecrets();

        expect(core.exportVariable).toBeCalledWith('KEY', '1');
        expect(core.setOutput).toBeCalledWith('key', '1');
    });

    it('nested secret retrieval', async () => {
        mockInput('test key.value');
        mockVaultData({
            key: { value: 1 }
        });

        await exportSecrets();

        expect(core.exportVariable).toBeCalledWith('KEY__VALUE', '1');
        expect(core.setOutput).toBeCalledWith('key__value', '1');
        core.Secre
    });

    it('export Vault token', async () => {
        mockInput('test key');
        mockVaultData({
            key: 1
        });
        mockExportToken("true")

        await exportSecrets();

        expect(core.exportVariable).toBeCalledTimes(2);

        expect(core.exportVariable).toBeCalledWith('VAULT_TOKEN', 'EXAMPLE');
        expect(core.exportVariable).toBeCalledWith('KEY', '1');
        expect(core.setOutput).toBeCalledWith('key', '1');
    });

    it('not export Vault token', async () => {
        mockInput('test key');
        mockVaultData({
            key: 1
        });
        mockExportToken("false")

        await exportSecrets();

        expect(core.exportVariable).toBeCalledTimes(1);

        expect(core.exportVariable).toBeCalledWith('KEY', '1');
        expect(core.setOutput).toBeCalledWith('key', '1');
    });

    it('single-line secret gets masked', async () => {
        mockInput('test key');
        mockVaultData({
            key: 'secret'
        });
        mockExportToken("false")

        await exportSecrets();

        expect(core.setSecret).toBeCalledTimes(2);

        expect(core.setSecret).toBeCalledWith('secret');
        expect(core.setOutput).toBeCalledWith('key', 'secret');
    })

    it('multi-line secret', async () => {
        const multiLineString = `ssh-rsa AAAAB3NzaC1yc2EAAAABIwAAAQEAklOUpkDHrfHY17SbrmTIpNLTGK9Tjom/BWDSU
GPl+nafzlHDTYW7hdI4yZ5ew18JH4JW9jbhUFrviQzM7xlELEVf4h9lFX5QVkbPppSwg0cda3
Pbv7kOdJ/MTyBlWXFCR+HAo3FXRitBqxiX1nKhXpHAZsMciLq8V6RjsNAQwdsdMFvSlVK/7XA
NrRFi9wrf+M7Q==`;

        mockInput('test key');
        mockVaultData({
            key: multiLineString
        });
        mockExportToken("false")

        await exportSecrets();

        expect(core.setSecret).toBeCalledTimes(5); // 1 for each non-empty line + VAULT_TOKEN

        expect(core.setSecret).toBeCalledWith("ssh-rsa AAAAB3NzaC1yc2EAAAABIwAAAQEAklOUpkDHrfHY17SbrmTIpNLTGK9Tjom/BWDSU");
        expect(core.setSecret).toBeCalledWith("GPl+nafzlHDTYW7hdI4yZ5ew18JH4JW9jbhUFrviQzM7xlELEVf4h9lFX5QVkbPppSwg0cda3");
        expect(core.setSecret).toBeCalledWith("Pbv7kOdJ/MTyBlWXFCR+HAo3FXRitBqxiX1nKhXpHAZsMciLq8V6RjsNAQwdsdMFvSlVK/7XA");
        expect(core.setSecret).toBeCalledWith("NrRFi9wrf+M7Q==");
        expect(core.setOutput).toBeCalledWith('key', multiLineString);
    })

    it('multi-line secret gets masked for each non-empty line', async () => {
        const multiLineString = `a multi-line string

with blank lines

`
        mockInput('test key');
        mockVaultData({
            key: multiLineString
        });
        mockExportToken("false")

        await exportSecrets();

        expect(core.setSecret).toBeCalledTimes(3); // 1 for each non-empty line.

        expect(core.setSecret).toBeCalledWith('a multi-line string');
        expect(core.setSecret).toBeCalledWith('with blank lines');
        expect(core.setOutput).toBeCalledWith('key', multiLineString);
    })

  it('export only Vault token, no secrets', async () => {
    mockExportToken("true")

    await exportSecrets();

    expect(core.exportVariable).toBeCalledTimes(1);
    expect(core.exportVariable).toBeCalledWith('VAULT_TOKEN', 'EXAMPLE');
  })

  it('output only Vault token, no secrets', async () => {
    mockOutputToken("true")

    await exportSecrets();

    expect(core.setOutput).toBeCalledTimes(1);
    expect(core.setOutput).toBeCalledWith('vault_token', 'EXAMPLE');
  })
  function mockExportGitHubSecrets(doExport) {
    when(core.getInput)
        .calledWith('exportGitHubSecrets', expect.anything())
        .mockReturnValueOnce(doExport);
    when(core.getInput)
        .calledWith('pat', expect.anything())
        .mockReturnValueOnce('personal-access-token');

  }

  it('export GitHub Secrets', async () => {
    mockExportGitHubSecrets("true");
    mockInput('test key');
    mockVaultData({
      key: 'secret'
    });
    await exportSecrets();

    expect(ghsecrets.exportGitHubSecret).toBeCalledTimes(1);
    expect(ghsecrets.exportGitHubSecret).toBeCalledWith('personal-access-token','KEY', 'secret');
  });
});
