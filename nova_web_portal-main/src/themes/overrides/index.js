// third-party
import { merge } from 'lodash';

// project import
import Alert from './Alert';
import Badge from './Badge';
import Button from './Button';
import CardContent from './CardContent';
import Checkbox from './Checkbox';
import Chip from './Chip';
import IconButton from './IconButton';
import InputLabel from './InputLabel';
import LinearProgress from './LinearProgress';
import Link from './Link';
import ListItemIcon from './ListItemIcon';
import OutlinedInput from './OutlinedInput';
import Snackbar from './Snackbar';
import Tab from './Tab';
import TableCell from './TableCell';
import Tabs from './Tabs';
import Typography from './Typography';

// ==============================|| OVERRIDES - MAIN ||============================== //

export default function ComponentsOverrides(theme) {
    return merge(
        Alert(theme),
        Button(theme),
        Badge(theme),
        CardContent(),
        Checkbox(theme),
        Chip(theme),
        IconButton(theme),
        InputLabel(theme),
        LinearProgress(),
        Link(),
        ListItemIcon(),
        OutlinedInput(theme),
        Snackbar(theme),
        Tab(theme),
        TableCell(theme),
        Tabs(),
        Typography()
    );
}
