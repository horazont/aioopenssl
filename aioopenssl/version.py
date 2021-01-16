version_info = (0, 6, 0, None)

__version__ = ".".join(map(str, version_info[:3])) + (
    "-"+version_info[3] if version_info[3] is not None else ""  # type:ignore
)

version = __version__
