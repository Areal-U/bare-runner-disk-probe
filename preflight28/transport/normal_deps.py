"""Stage the authenticated R26 Ubuntu transaction before a normal private build."""
from prepare import READ, commands, shell


def stage():
    recipe = commands(READ)
    shell(recipe["Acquire all six pinned payloads before the cache and source checkout"])
    shell(recipe["Stage the reviewed fixed-index Ubuntu package verifier"])


if __name__ == "__main__":
    stage()
