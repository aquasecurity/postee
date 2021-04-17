package postee

default allow = false

allow {
    contains(input.action, "Login")
}