diesel::table! {
    use diesel::sql_types::*;

    users (id) {
        id -> Uuid,
        email -> Text,
        display_name -> Nullable<Text>,
        password_hash -> Text,
        created_at -> Timestamptz,
        updated_at -> Timestamptz,
    }
}
