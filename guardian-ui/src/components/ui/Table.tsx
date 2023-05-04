import {
  Text,
  TableContainer,
  Table as ChakraTable,
  Thead,
  Th,
  Tbody,
  Tr,
  Td,
  Box,
  useTheme,
} from '@chakra-ui/react';

export interface TableColumn<T extends string> {
  key: T;
  heading: React.ReactNode;
}

export type TableRow<T extends string> = { key: number | string } & {
  [key in T]: React.ReactNode;
};

export interface TableProps<T extends string> {
  title?: React.ReactNode;
  description?: React.ReactNode;
  columns: Readonly<TableColumn<T>[]>;
  rows: Readonly<TableRow<T>[]>;
}

export function Table<T extends string>({
  title,
  description,
  columns,
  rows,
}: TableProps<T>): React.ReactElement {
  const theme = useTheme();
  const hasHeading = Boolean(title || description);
  const border = `1px solid ${theme.colors.border.table}`;
  return (
    <Box
      background={theme.colors.white}
      border={border}
      boxShadow={theme.shadows.sm}
      borderRadius={12}
      width='100%'
    >
      {hasHeading && (
        <Box
          display='flex'
          flexDirection='column'
          gap={1}
          p={6}
          borderBottom={border}
        >
          {title && (
            <Text size='lg' fontWeight='600'>
              {title}
            </Text>
          )}
          {description && (
            <Text variant='secondary' size='sm'>
              {description}
            </Text>
          )}
        </Box>
      )}
      <TableContainer>
        <ChakraTable style={{ borderCollapse: 'separate' }}>
          <Thead>
            <Tr>
              {columns.map((column) => (
                <Th key={column.key} borderBottom={border} bg='#F9FAFB'>
                  {column.heading}
                </Th>
              ))}
            </Tr>
          </Thead>
          <Tbody>
            {rows.map((row, idx) => (
              <Tr key={row.key}>
                {columns.map((column) => (
                  <Td
                    key={column.key}
                    borderBottom={border}
                    borderBottomWidth={idx === rows.length - 1 ? 0 : 1}
                    height='72px'
                  >
                    {row[column.key]}
                  </Td>
                ))}
              </Tr>
            ))}
          </Tbody>
        </ChakraTable>
      </TableContainer>
    </Box>
  );
}
