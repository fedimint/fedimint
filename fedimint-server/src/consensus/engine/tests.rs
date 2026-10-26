use super::{ScheduledShutdown, ShutdownRequest, due_shutdown};

#[test]
fn shutdown_takes_effect_at_the_first_boundary_at_or_after_its_session() {
    let at = |session| {
        Some(ScheduledShutdown {
            session,
            request: ShutdownRequest::AtSession,
        })
    };
    assert_eq!(due_shutdown(None, 0), None);
    assert_eq!(due_shutdown(at(5), 4), None);
    assert_eq!(due_shutdown(at(5), 5), Some(ShutdownRequest::AtSession));
    // Scheduled while session 5 was completing: the next boundary.
    assert_eq!(due_shutdown(at(5), 6), Some(ShutdownRequest::AtSession));
}
