use std::sync::Arc;

use fedimint_core::task::{MaybeSend, MaybeSync};

use crate::sm::StateTransition;

pub trait MapStateTransitions {
    type State: MaybeSend + MaybeSync + 'static;

    fn map<D, W, U>(self, wrap: W, unwrap: U) -> Vec<StateTransition<D>>
    where
        D: MaybeSend + MaybeSync + 'static,
        W: Fn(Self::State) -> D + Clone + MaybeSend + MaybeSync + 'static,
        U: Fn(D) -> Self::State + Clone + MaybeSend + MaybeSync + 'static;
}

impl<S> MapStateTransitions for Vec<StateTransition<S>>
where
    S: MaybeSend + MaybeSync + 'static,
{
    type State = S;

    fn map<D, W, U>(self, wrap: W, unwrap: U) -> Vec<StateTransition<D>>
    where
        D: MaybeSend + MaybeSync + 'static,
        W: Fn(Self::State) -> D + Clone + MaybeSend + MaybeSync + 'static,
        U: Fn(D) -> Self::State + Clone + MaybeSend + MaybeSync + 'static,
    {
        self.into_iter()
            .map(
                |StateTransition {
                     trigger,
                     transition,
                 }| {
                    let wrap = wrap.clone();
                    let unwrap = unwrap.clone();
                    StateTransition {
                        trigger,
                        transition: Arc::new(move |dbtx, value, state| {
                            let wrap = wrap.clone();
                            let unwrap = unwrap.clone();
                            let transition = transition.clone();
                            Box::pin(
                                async move { wrap(transition(dbtx, value, unwrap(state)).await) },
                            )
                        }),
                    }
                },
            )
            .collect()
    }
}

#[macro_export]
macro_rules! sm_enum_variant_translation {
    ($sm:expr, $enum_variant:path) => {
        $sm.map(
            |sm| $enum_variant(sm),
            |sm| match sm {
                $enum_variant(sm) => sm,
                _ => panic!("Incorrectly dispatched state"),
            },
        )
    };
}
