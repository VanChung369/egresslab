// A quiet refresh is skipped while another one runs. Any other refresh supersedes the running ones,
// so only the newest refresh applies its results.
export function createRefreshGate() {
  let latest = 0;
  let running = 0;

  return {
    start(quiet: boolean): number | undefined {
      if (quiet && running > 0) return undefined;

      running += 1;
      latest += 1;

      return latest;
    },
    isLatest: (ticket: number) => ticket === latest,
    finish(): void {
      running -= 1;
    }
  };
}
