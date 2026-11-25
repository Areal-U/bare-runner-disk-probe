"""Stage the authenticated R26 Ubuntu transaction before a normal private build."""
from prepare import recipe, shell


def stage():
    shell(recipe("fetch_six.sh"))
    shell(recipe("install_six.sh"))


if __name__ == "__main__":
    stage()
