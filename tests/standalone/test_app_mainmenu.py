from ledgered.devices import Device
from ragger.navigator import Navigator, NavInsID


# In this test we check the behavior of the device main menu:
# home screen, then the app info (version, usage), then back home
def test_app_mainmenu(device: Device, navigator: Navigator, test_name: str, default_screenshot_path: str) -> None:
    instructions: list[NavInsID] = []
    if device.is_nano:
        instructions += [
            NavInsID.RIGHT_CLICK,  # "App info"
            NavInsID.BOTH_CLICK,  # enter: Version
            NavInsID.RIGHT_CLICK,  # Usage
            NavInsID.RIGHT_CLICK,  # Back
            NavInsID.BOTH_CLICK,  # back to "App info"
            NavInsID.RIGHT_CLICK,  # "Quit app"
        ]
    else:
        instructions += [
            NavInsID.USE_CASE_HOME_SETTINGS,
            NavInsID.USE_CASE_SETTINGS_MULTI_PAGE_EXIT,
        ]

    navigator.navigate_and_compare(
        default_screenshot_path,
        test_name,
        instructions,
        screen_change_before_first_instruction=False,
    )
