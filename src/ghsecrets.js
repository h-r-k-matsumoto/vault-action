const core = require("@actions/core")
const github = require("@actions/github")
const sodium = require('libsodium-wrappers')

async function encrypt(public_key,value) {
  await sodium.ready;
  let binkey = sodium.from_base64(public_key, sodium.base64_variants.ORIGINAL)
  let binsec = sodium.from_string(value)
  let encBytes = sodium.crypto_box_seal(binsec, binkey)

  return sodium.to_base64(encBytes, sodium.base64_variants.ORIGINAL)
}

async function exportGitHubSecret(pat, secret_name, value) {
  try {
    const octokit = github.getOctokit(pat);
    const {owner, repo} = github.context.repo;
    const public_key = await octokit.rest.actions.getRepoPublicKey({owner,repo});
    const key_id = public_key.data.key_id;

    encrypted_value = await encrypt(public_key.data.key,value);

    await octokit.rest.actions.createOrUpdateRepoSecret({
      owner,
      repo,
      secret_name,
      encrypted_value,
      key_id,
    });

  } catch (err) {
    core.debug(`xxxx ${secret_name}`);
    core.debug(err.name);
    core.debug(err.message);
    core.debug(err.stack);
    core.setFailed(err.message);
  }
}

module.exports = {
  exportGitHubSecret
}
