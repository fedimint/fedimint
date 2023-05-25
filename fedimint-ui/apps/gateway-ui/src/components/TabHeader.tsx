import React from 'react';
import { Button, useTab, useMultiStyleConfig } from '@chakra-ui/react';

interface TabHeaderProps {
  children?: React.ReactNode;
}

export const TabHeader = React.forwardRef(function TabHeader(
  props: TabHeaderProps,
  ref?: React.Ref<HTMLElement> | undefined
): JSX.Element {
  const tabProps = useTab({ ...props, ref });
  const styles = useMultiStyleConfig('Tabs', tabProps);

  return (
    <Button __css={styles.tab} {...tabProps}>
      {tabProps.children}
    </Button>
  );
});
