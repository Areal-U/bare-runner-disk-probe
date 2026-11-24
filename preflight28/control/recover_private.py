"""Receive an existing owner-Draft checkpoint using only GET/HEAD from the original run."""
import os
from pathlib import Path
import sys

from admission import BASE_REF, REPO, require


def read_only(request):
    def restricted(host, method, path, **kwargs):
        require(method in ("GET", "HEAD") and kwargs.get("body") is None and
                not any(k in kwargs for k in ("length", "content_type")), "Manual recovery permits reads only")
        return request(host, method, path, **kwargs)
    return restricted


def main():
    e=os.environ
    require(int(e["GITHUB_RUN_ATTEMPT"]) > 1 and e["GITHUB_REPOSITORY"] == REPO and
            e["GITHUB_REF"] == "refs/heads/"+BASE_REF and e["GITHUB_EVENT_NAME"]=="workflow_dispatch"
            and e["GITHUB_JOB"]=="recover-draft-checkpoint", "Unexpected recovery caller")
    sys.path[:0]=[str(Path(__file__).resolve().parents[1]/"bridge"),e["RUNNER_TEMP"]]
    import normal
    import transfer
    transfer.request=read_only(transfer.request)
    normal.recover()


if __name__=="__main__":
    main()
