import React from 'react';
import {
	Menu,
	MenuButton,
	MenuItem,
	MenuList,
	Flex,
	Spacer,
	IconButton,
	Stack,
	MenuDivider,
	MenuGroup,
} from '@chakra-ui/react';
import { Button as ChakraButton } from '@chakra-ui/react';
import { FiChevronDown } from 'react-icons/fi';
import { HiMenuAlt3 } from 'react-icons/hi';
import { Federation, Filter, Sort } from '../federation.types';
import { Button } from '.';
import '../index.css';

export type HeaderProps = {
	data: Federation[];
	toggleShowConnectFed: () => void;
	filterCallback: (filter: Filter) => void;
	sortCallback: (sort: Sort) => void;
};

export const Header = React.memo(function Header(
	props: HeaderProps
): JSX.Element {
	return (
		<Flex>
			<Flex alignItems='center' gap={2}>
				<Button
					onClick={props.toggleShowConnectFed}
					fontSize={{ base: '12px', md: '13px', lg: '16px' }}
					p={{ base: '10px', md: '13px', lg: '16px' }}
				>
					Connect Federation
				</Button>
			</Flex>
			<Spacer />
			<div className='button-menu'>
				<Flex alignItems='center' gap='2' className='button-menu'>
					{/* sort menu button */}
					<Menu>
						<MenuButton
							fontSize={{ base: '12px', md: '13px', lg: '16px' }}
							as={ChakraButton}
							rightIcon={<FiChevronDown />}
						>
							Sort
						</MenuButton>
						<MenuList>
							<MenuItem onClick={() => props.sortCallback(Sort.Ascending)}>
								Ascending
							</MenuItem>
							<MenuItem onClick={() => props.sortCallback(Sort.Descending)}>
								Descending
							</MenuItem>
							<MenuItem onClick={() => props.sortCallback(Sort.Date)}>
								Date Created
							</MenuItem>
						</MenuList>
					</Menu>
					{/* filter menu button */}
					<Menu>
						<MenuButton
							fontSize={{ base: '12px', md: '13px', lg: '16px' }}
							as={ChakraButton}
							rightIcon={<FiChevronDown />}
						>
							Filter
						</MenuButton>
						<MenuList>
							<MenuItem onClick={() => props.filterCallback(true)}>
								Active
							</MenuItem>
							<MenuItem onClick={() => props.filterCallback(false)}>
								Archived
							</MenuItem>
							<MenuItem onClick={() => props.filterCallback(undefined)}>
								All
							</MenuItem>
						</MenuList>
					</Menu>
				</Flex>
			</div>

			<div className='icon-menu'>
				<Stack ml='2' className='icon-name'>
					<Menu>
						<MenuButton
							as={IconButton}
							aria-label='Options'
							icon={<HiMenuAlt3 />}
							variant='outline'
						/>
						<MenuList>
							<MenuGroup title='Sort'>
								<MenuItem
									fontSize={[14, 15, 16]}
									onClick={() => props.sortCallback(Sort.Ascending)}
								>
									Ascending
								</MenuItem>
								<MenuItem
									fontSize={[14, 15, 16]}
									onClick={() => props.sortCallback(Sort.Descending)}
								>
									Descending
								</MenuItem>
								<MenuItem
									fontSize={[14, 15, 16]}
									onClick={() => props.sortCallback(Sort.Date)}
								>
									Date Created
								</MenuItem>
							</MenuGroup>
							<MenuDivider />
							<MenuGroup title='Filter'>
								<MenuItem
									fontSize={[14, 15, 16]}
									onClick={() => props.filterCallback(true)}
								>
									Active
								</MenuItem>
								<MenuItem
									fontSize={[14, 15, 16]}
									onClick={() => props.filterCallback(false)}
								>
									Archived
								</MenuItem>
								<MenuItem
									fontSize={[14, 15, 16]}
									onClick={() => props.filterCallback(undefined)}
								>
									All
								</MenuItem>
							</MenuGroup>
						</MenuList>
					</Menu>
				</Stack>
			</div>
		</Flex>
	);
});
