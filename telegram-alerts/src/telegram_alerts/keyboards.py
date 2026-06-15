def reply(text, reply_markup=None, remove_keyboard=False):
    data = {"text": str(text)}
    if reply_markup:
        data["reply_markup"] = reply_markup
    if remove_keyboard:
        data["remove_keyboard"] = True
    return data

def silent_reply(remove_keyboard=False):
    data = {"skip_send": True}
    if remove_keyboard:
        data["remove_keyboard"] = True
    return data

def inline_keyboard(rows):
    return {"inline_keyboard": rows}

def button(text, callback_data):
    return {"text": text, "callback_data": callback_data}

def after_confirm_callback(callback_data):
    return f"after:{callback_data}"

def menu_keyboard():
    return inline_keyboard([
        [button("Capacity Check", "menu:capacity"), button("Top Users", "menu:top")],
        [button("Quota Management", "menu:quota_management"), button("Key Status", "menu:key_status")],
        [button("Health Alerts", "menu:incidents"), button("Errors Today", "menu:errors")],
        [button("Edit Quota", "menu:quota_set"), button("Create Key", "menu:key_create")],
    ])


def key_status_keyboard():
    return inline_keyboard([
        [button("Disable key", "menu:key_disable"), button("Enable key", "menu:key_enable")],
        [button("Delete key", "menu:key_delete"), button("Show key", "menu:key_lookup")],
        [button("Menu", "menu:back"), button("Refresh", "menu:key_status_refresh")],
    ])

def back_keyboard(refresh_data, extra_rows=None):
    rows = [[button("Menu", "menu:back"), button("Refresh", refresh_data)]]
    if extra_rows:
        rows.extend(extra_rows)
    return inline_keyboard(rows)


def key_reveal_actions_keyboard():
    return inline_keyboard([[button("Menu", "menu:back"), button("Show another key", "menu:key_lookup")]])


def quota_update_actions_keyboard(quota_kind=None, same_key_callback=None):
    if quota_kind == "daily" and same_key_callback:
        return inline_keyboard([
            [button("Edit weekly quota", after_confirm_callback(same_key_callback)), button("Edit another key", after_confirm_callback("menu:quota_set"))],
            [button("Menu", after_confirm_callback("menu:back"))],
        ])
    if quota_kind == "weekly" and same_key_callback:
        return inline_keyboard([
            [button("Edit daily quota", after_confirm_callback(same_key_callback)), button("Edit another key", after_confirm_callback("menu:quota_set"))],
            [button("Menu", after_confirm_callback("menu:back"))],
        ])
    return inline_keyboard([[button("Menu", after_confirm_callback("menu:back")), button("Edit another key", after_confirm_callback("menu:quota_set"))]])


def key_create_actions_keyboard():
    return inline_keyboard([[button("Menu", after_confirm_callback("menu:back")), button("Create another key", after_confirm_callback("menu:key_create"))]])


def key_management_success_actions_keyboard(action_type):
    if action_type == "key_disable":
        return inline_keyboard([
            [button("Key Status", after_confirm_callback("menu:key_status")), button("Disable another key", after_confirm_callback("menu:key_disable"))],
            [button("Menu", after_confirm_callback("menu:back"))],
        ])
    if action_type == "key_enable":
        return inline_keyboard([
            [button("Key Status", after_confirm_callback("menu:key_status")), button("Enable another key", after_confirm_callback("menu:key_enable"))],
            [button("Menu", after_confirm_callback("menu:back"))],
        ])
    if action_type == "key_delete":
        return inline_keyboard([
            [button("Key Status", after_confirm_callback("menu:key_status")), button("Delete another key", after_confirm_callback("menu:key_delete"))],
            [button("Menu", after_confirm_callback("menu:back"))],
        ])
    return inline_keyboard([[button("Menu", after_confirm_callback("menu:back"))]])


def top_users_keyboard():
    return inline_keyboard([
        [button("Menu", "menu:back"), button("Usage", "menu:usage")],
        [button("Refresh", "menu:top_refresh")],
    ])


def errors_keyboard():
    return inline_keyboard([[button("Menu", "menu:back"), button("Refresh", "menu:errors_refresh")]])
