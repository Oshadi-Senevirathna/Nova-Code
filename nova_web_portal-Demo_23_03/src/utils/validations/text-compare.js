const textCompare = (right, left) => {
    var split_left = left.split(/\r\n|\r|\n/);
    var split_right = right.split(/\r\n|\r|\n/);

    var compared_left = [];
    var compared_right = [];

    var currentLine = 0;
    for (let i = 0; i < split_right.length; i++) {
        var matchFound = false;
        for (let j = currentLine; j < split_left.length; j++) {
            if (split_left[j] === split_right[i] && split_right[i] !== '!') {
                if (j !== currentLine) {
                    for (let q = currentLine; q < j; q++) {
                        if (split_left[q] !== '!') {
                            var temp_left_deleted = {};
                            temp_left_deleted.line = split_left[q];
                            temp_left_deleted.status = 'ADDED';
                            compared_left.push(temp_left_deleted);

                            var temp_right_deleted = {};
                            temp_right_deleted.line = ' ';
                            temp_right_deleted.status = 'EMPTY';
                            compared_right.push(temp_right_deleted);
                        }
                    }
                }
                var temp_left_line = {};
                temp_left_line.line = split_left[j];
                temp_left_line.status = 'MATCH';
                var temp_right_line = {};
                temp_right_line.line = split_right[i];
                temp_right_line.status = 'MATCH';
                compared_left.push(temp_left_line);
                compared_right.push(temp_right_line);
                currentLine = j + 1;
                matchFound = true;
                break;
            }
        }
        if (matchFound === false && split_right[i] !== '!') {
            var temp_right_added = {};
            temp_right_added.line = split_right[i];
            temp_right_added.status = 'DELETED';
            compared_right.push(temp_right_added);

            var temp_left_added = {};
            temp_left_added.line = ' ';
            temp_left_added.status = 'EMPTY';
            compared_left.push(temp_left_added);
        }
    }
    return [compared_left, compared_right];
};

export default textCompare;
