def pytest_addoption(parser):
    parser.addoption(
        "--snapshot-update",
        action="store_true",
        default=False,
        help="rewrite committed snapshots instead of asserting against them",
    )
