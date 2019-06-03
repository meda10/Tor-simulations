function show_layer(num) {
	var layers = document.querySelectorAll("svg g.layer");
	
	if (layers.length > 0) {
		layers[num].classList.remove("hidden");
		var button = document.createElement("button");
		button.className='btn btn-primary';
		var link = document.createElement("a");
		button.appendChild(link);

		function show_next(next_num) {
			document.getElementById("link-container").removeChild(button);
			layers[num].classList.add("hidden");
			show_layer(next_num);
		}
		
		var next_num = (num + 1) % layers.length;
		link.onclick = show_next.bind(null, next_num);
		link.href = "#" + next_num;
		link.text = next_num == 0 ? "Restart" : "Next";
		document.getElementById("link-container").appendChild(button);
	}
}

document.addEventListener("DOMContentLoaded", function () {
	var layers = document.querySelectorAll("svg g.layer");
	[].forEach.call(layers, e => e.classList.add("hidden"));
	var layer = parseInt(window.location.hash.substr(1));
	if (layer !== "NaN" && layer < layers.length) {
		show_layer(layer);
	} else {
		show_layer(0);
	}
});

//<button type="button" class="btn btn-primary">Primary</button>